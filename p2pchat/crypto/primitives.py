"""Криптографические примитивы для набора Noise_XX_25519_ChaChaPoly_BLAKE2s.

Единственная внешняя зависимость — пакет ``cryptography``. Модуль намеренно
тонкий: он не принимает решений, а только приводит библиотечные API к тем
именам и сигнатурам, которыми оперирует спецификация Noise (revision 34).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = [
    "DHLEN",
    "HASHLEN",
    "TAGLEN",
    "MAX_NONCE",
    "KeyPair",
    "InvalidTag",
    "dh",
    "hash_",
    "hmac_hash",
    "hkdf",
    "encrypt",
    "decrypt",
]

DHLEN = 32
HASHLEN = 32
TAGLEN = 16
KEYLEN = 32

# Noise запрещает использовать счётчик 2**64 - 1 для обычных сообщений:
# это значение зарезервировано под Rekey().
MAX_NONCE = 2**64 - 1


class BadKeyExchange(Exception):
    """DH дал вырожденный результат — публичный ключ пира некорректен."""


@dataclass(frozen=True)
class KeyPair:
    """Пара ключей X25519. ``public`` хранится в сыром 32-байтовом виде."""

    private: X25519PrivateKey
    public: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = X25519PrivateKey.generate()
        return cls(private=sk, public=_public_bytes(sk))

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        if len(raw) != DHLEN:
            raise ValueError(f"приватный ключ должен быть {DHLEN} байт, получено {len(raw)}")
        sk = X25519PrivateKey.from_private_bytes(raw)
        return cls(private=sk, public=_public_bytes(sk))

    def private_bytes(self) -> bytes:
        return self.private.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )


def _public_bytes(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def dh(keypair: KeyPair, public: bytes) -> bytes:
    """DH(секретный ключ, чужой публичный ключ) -> общий секрет.

    X25519 отображает точки малого порядка в нулевой результат. Спецификация
    Noise разрешает такой результат не проверять, но мы проверяем: нулевой
    общий секрет означает, что пир прислал заведомо негодный ключ, и молча
    продолжать хендшейк в этой ситуации незачем.
    """
    if len(public) != DHLEN:
        raise ValueError(f"публичный ключ должен быть {DHLEN} байт, получено {len(public)}")
    try:
        shared = keypair.private.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as exc:
        # OpenSSL сам отвергает точки малого порядка. Приводим к своему типу,
        # чтобы вызывающий код не разбирал текст чужого сообщения об ошибке.
        raise BadKeyExchange("публичный ключ пира вырожден") from exc
    if shared == bytes(DHLEN):
        raise BadKeyExchange("общий секрет нулевой: публичный ключ пира вырожден")
    return shared


def hash_(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def hmac_hash(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> tuple[bytes, ...]:
    """HKDF в том виде, в каком его определяет раздел 4.3 спецификации Noise."""
    if num_outputs not in (2, 3):
        raise ValueError("num_outputs должен быть 2 или 3")
    temp_key = hmac_hash(chaining_key, input_key_material)
    output1 = hmac_hash(temp_key, b"\x01")
    output2 = hmac_hash(temp_key, output1 + b"\x02")
    if num_outputs == 2:
        return output1, output2
    output3 = hmac_hash(temp_key, output2 + b"\x03")
    return output1, output2, output3


def _nonce_bytes(n: int) -> bytes:
    """96-битный nonce: 32 нулевых бита, затем счётчик little-endian."""
    if not 0 <= n <= MAX_NONCE:
        raise ValueError("счётчик nonce вне диапазона")
    return b"\x00\x00\x00\x00" + n.to_bytes(8, "little")


def encrypt(key: bytes, nonce: int, associated_data: bytes, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(_nonce_bytes(nonce), plaintext, associated_data)


def decrypt(key: bytes, nonce: int, associated_data: bytes, ciphertext: bytes) -> bytes:
    """Расшифровывает и проверяет тег. При несовпадении бросает ``InvalidTag``."""
    return ChaCha20Poly1305(key).decrypt(_nonce_bytes(nonce), ciphertext, associated_data)
