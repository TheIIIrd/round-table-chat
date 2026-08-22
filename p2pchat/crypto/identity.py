"""Долговременная идентичность пира: пара X25519 и её хранение на диске.

Формат файла ключа::

    magic(11) | version(1) | t_cost(1) | lanes(1) | m_cost_kib(4, BE)
              | salt(16) | nonce(12) | ciphertext(32 + 16)

Соль генерируется заново при каждом сохранении, поэтому ключ шифрования
файла каждый раз новый и повторное использование nonce исключено.

Оговорка, которую нельзя замалчивать: в Python ключ невозможно надёжно
затереть в памяти. ``bytes`` неизменяемы, сборщик мусора копирует объекты,
страница может уйти в swap. Против противника с доступом к работающей машине
или к дампу памяти это хранилище не защищает — оно защищает только выключенный
диск.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import primitives as p

MAGIC = b"P2PCHATKEY1"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12

# ~256 МиБ, 3 прохода, 4 потока. Ощутимо для интерактивного ввода (доли
# секунды), но делает перебор пассфразы дорогим.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 256 * 1024
ARGON2_LANES = 4


class KeyFileError(Exception):
    """Файл ключа повреждён, имеет чужой формат или пассфраза неверна."""


@dataclass(frozen=True)
class Identity:
    """Статическая пара ключей пира (человека или бота)."""

    keypair: p.KeyPair
    nickname: str = ""

    @classmethod
    def generate(cls, nickname: str = "") -> "Identity":
        return cls(keypair=p.KeyPair.generate(), nickname=nickname)

    @property
    def public(self) -> bytes:
        return self.keypair.public

    def fingerprint(self) -> str:
        """Отпечаток публичного ключа для сверки при первом контакте."""
        return fingerprint(self.keypair.public)

    def save(self, path: str | Path, passphrase: str) -> None:
        if not passphrase:
            raise ValueError("пустая пассфраза недопустима")
        salt = secrets.token_bytes(SALT_LEN)
        nonce = secrets.token_bytes(NONCE_LEN)
        header = (
            MAGIC
            + bytes([VERSION, ARGON2_TIME_COST, ARGON2_LANES])
            + ARGON2_MEMORY_KIB.to_bytes(4, "big")
            + salt
            + nonce
        )
        key = _derive(passphrase, salt, ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_LANES)
        # Заголовок идёт в associated data: подмена параметров Argon2
        # (например, понижение стоимости) сломает проверку тега.
        blob = p.encrypt(key, 0, header, self.keypair.private_bytes())

        path = Path(path)
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(header + blob)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: str | Path, passphrase: str, nickname: str = "") -> "Identity":
        raw = Path(path).read_bytes()
        header, params, blob = _split_key_file(raw)
        key = _derive(passphrase, *params)
        try:
            private = p.decrypt(key, 0, header, blob)
        except p.InvalidTag as exc:
            raise KeyFileError("неверная пассфраза или файл повреждён") from exc
        return cls(keypair=p.KeyPair.from_private_bytes(private), nickname=nickname)


HEADER_LEN = len(MAGIC) + 3 + 4 + SALT_LEN + NONCE_LEN


def _split_key_file(raw: bytes) -> tuple[bytes, tuple[bytes, int, int, int], bytes]:
    """Разбирает файл ключа на заголовок, параметры Argon2id и шифротекст."""
    if len(raw) != HEADER_LEN + p.DHLEN + p.TAGLEN:
        raise KeyFileError("некорректный размер файла ключа")
    if raw[: len(MAGIC)] != MAGIC:
        raise KeyFileError("это не файл ключа p2pchat")

    version, t_cost, lanes = raw[len(MAGIC)], raw[len(MAGIC) + 1], raw[len(MAGIC) + 2]
    if version != VERSION:
        raise KeyFileError(f"неподдерживаемая версия формата: {version}")

    at = len(MAGIC) + 3
    m_cost = int.from_bytes(raw[at : at + 4], "big")
    salt = raw[at + 4 : at + 4 + SALT_LEN]
    return raw[:HEADER_LEN], (salt, t_cost, m_cost, lanes), raw[HEADER_LEN:]


def _derive(passphrase: str, salt: bytes, t_cost: int, m_cost: int, lanes: int) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=p.KEYLEN,
        iterations=t_cost,
        lanes=lanes,
        memory_cost=m_cost,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def fingerprint(public: bytes, groups: int = 8) -> str:
    """Отпечаток вида ``a1b2 c3d4 ...`` — 16 байт BLAKE2s от публичного ключа."""
    digest = p.hash_(b"p2pchat-fingerprint-v1" + public)[:16]
    hexed = digest.hex()
    step = len(hexed) // groups
    return " ".join(hexed[i : i + step] for i in range(0, len(hexed), step))
