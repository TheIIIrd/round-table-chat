"""Передача файлов внутри уже защищённого канала.

Логика сознательно отделена от сети: здесь два конечных автомата, которые
только разбирают и собирают тела сообщений. Благодаря этому весь протокол
передачи тестируется без сокетов.

Три вещи, которые тут важнее скорости:

* **Имя файла санитизируется.** Присланное имя — это данные от постороннего.
  ``../../.ssh/authorized_keys`` не должно превращаться в путь.
* **Размер ограничен и проверяется до начала приёма**, а не по факту.
* **Хеш проверяется целиком**, и файл появляется в каталоге назначения только
  после проверки — через временный файл и атомарное переименование. Иначе на
  диске оставался бы наполовину принятый файл с настоящим именем.

Передача идёт конкретному участнику, а не всей группе. В концепции
предполагалась рассылка всем, но в консольном чате это почти всегда не то, что
нужно: файл дублируется по числу участников, а адресат обычно один.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

TRANSFER_ID_LEN = 16
CHUNK_SIZE = 32 * 1024
MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_NAME_LEN = 120
HASH_LEN = 32

_UNSAFE = re.compile(r"[\x00-\x1f\x7f/\\]")


class TransferError(Exception):
    """Нарушение протокола передачи файла."""


class TransferState(Enum):
    OFFERED = "offered"
    ACTIVE = "active"
    DONE = "done"
    FAILED = "failed"
    DECLINED = "declined"


def sanitize_name(raw: str) -> str:
    """Превращает присланное имя в безопасное имя файла."""
    name = _UNSAFE.sub("_", raw).strip().strip(".")
    name = name[:MAX_NAME_LEN]
    if not name or name in {".", ".."}:
        name = "file"
    return name


def file_digest(path: Path) -> bytes:
    digest = hashlib.blake2b(digest_size=HASH_LEN)
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()


def unique_path(directory: Path, name: str) -> Path:
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    for index in range(1, 1000):
        candidate = directory / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
    raise TransferError("не удалось подобрать свободное имя файла")


# --- тела сообщений ---------------------------------------------------------


def encode_offer(transfer_id: bytes, size: int, digest: bytes, name: str) -> bytes:
    return transfer_id + size.to_bytes(8, "big") + digest + name.encode("utf-8")


def decode_offer(body: bytes) -> tuple[bytes, int, bytes, str]:
    head = TRANSFER_ID_LEN + 8 + HASH_LEN
    if len(body) <= head:
        raise TransferError("предложение файла обрезано")
    transfer_id = body[:TRANSFER_ID_LEN]
    size = int.from_bytes(body[TRANSFER_ID_LEN : TRANSFER_ID_LEN + 8], "big")
    digest = body[TRANSFER_ID_LEN + 8 : head]
    try:
        name = body[head:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransferError("имя файла не в UTF-8") from exc
    return transfer_id, size, digest, name


def encode_chunk(transfer_id: bytes, index: int, data: bytes) -> bytes:
    return transfer_id + index.to_bytes(4, "big") + data


def decode_chunk(body: bytes) -> tuple[bytes, int, bytes]:
    head = TRANSFER_ID_LEN + 4
    if len(body) <= head:
        raise TransferError("кусок файла обрезан")
    return body[:TRANSFER_ID_LEN], int.from_bytes(body[TRANSFER_ID_LEN:head], "big"), body[head:]


def decode_id(body: bytes) -> bytes:
    if len(body) != TRANSFER_ID_LEN:
        raise TransferError("некорректный идентификатор передачи")
    return body


# --- стороны передачи -------------------------------------------------------


@dataclass
class OutgoingTransfer:
    """Отправитель: читает файл кусками по мере подтверждений."""

    path: Path
    transfer_id: bytes = field(default_factory=lambda: secrets.token_bytes(TRANSFER_ID_LEN))
    state: TransferState = TransferState.OFFERED
    sent_bytes: int = 0

    def __post_init__(self) -> None:
        if not self.path.is_file():
            raise TransferError(f"нет такого файла: {self.path}")
        self.size = self.path.stat().st_size
        if self.size == 0:
            raise TransferError("пустой файл отправлять нечего")
        if self.size > MAX_FILE_SIZE:
            raise TransferError(f"файл больше лимита {MAX_FILE_SIZE // (1024 * 1024)} МиБ")
        self.digest = file_digest(self.path)
        self.name = sanitize_name(self.path.name)

    def offer_body(self) -> bytes:
        return encode_offer(self.transfer_id, self.size, self.digest, self.name)

    def chunks(self):
        """Генератор тел ``FILE_CHUNK``. Вызывается после подтверждения."""
        self.state = TransferState.ACTIVE
        with self.path.open("rb") as fh:
            index = 0
            while True:
                data = fh.read(CHUNK_SIZE)
                if not data:
                    break
                yield encode_chunk(self.transfer_id, index, data)
                self.sent_bytes += len(data)
                index += 1
        self.state = TransferState.DONE


@dataclass
class IncomingTransfer:
    """Получатель: пишет во временный файл, проверяет хеш, затем переносит."""

    transfer_id: bytes
    name: str
    size: int
    digest: bytes
    directory: Path
    state: TransferState = TransferState.OFFERED
    received_bytes: int = 0
    _next_index: int = 0
    _handle = None
    _temp: Path | None = None

    @classmethod
    def from_offer(cls, body: bytes, directory: Path) -> "IncomingTransfer":
        transfer_id, size, digest, raw_name = decode_offer(body)
        if size <= 0 or size > MAX_FILE_SIZE:
            raise TransferError(f"размер {size} вне допустимых границ")
        if len(digest) != HASH_LEN:
            raise TransferError("некорректный хеш в предложении")
        return cls(
            transfer_id=transfer_id,
            name=sanitize_name(raw_name),
            size=size,
            digest=digest,
            directory=Path(directory),
        )

    @property
    def is_active(self) -> bool:
        return self.state is TransferState.ACTIVE

    def accept(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._temp = self.directory / f".{self.transfer_id.hex()}.part"
        fd = os.open(self._temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self._handle = os.fdopen(fd, "wb")
        self.state = TransferState.ACTIVE

    def decline(self) -> None:
        self.state = TransferState.DECLINED
        self._cleanup()

    def add_chunk(self, body: bytes) -> None:
        if self.state is not TransferState.ACTIVE or self._handle is None:
            raise TransferError("кусок пришёл вне активной передачи")
        transfer_id, index, data = decode_chunk(body)
        if transfer_id != self.transfer_id:
            raise TransferError("кусок от другой передачи")
        if index != self._next_index:
            raise TransferError(f"ожидался кусок {self._next_index}, пришёл {index}")
        if self.received_bytes + len(data) > self.size:
            raise TransferError("прислано больше, чем было заявлено")
        self._handle.write(data)
        self.received_bytes += len(data)
        self._next_index += 1

    def finish(self) -> Path:
        if self.state is not TransferState.ACTIVE or self._handle is None or self._temp is None:
            raise TransferError("завершение вне активной передачи")
        self._handle.close()
        self._handle = None
        try:
            if self.received_bytes != self.size:
                raise TransferError(
                    f"получено {self.received_bytes} байт вместо заявленных {self.size}"
                )
            if file_digest(self._temp) != self.digest:
                raise TransferError("хеш не совпал — файл повреждён или подменён")
            target = unique_path(self.directory, self.name)
            os.replace(self._temp, target)
        except TransferError:
            self.state = TransferState.FAILED
            self._cleanup()
            raise
        self._temp = None
        self.state = TransferState.DONE
        return target

    def fail(self, reason: str) -> None:
        self.state = TransferState.FAILED
        self._cleanup()
        raise TransferError(reason)

    def _cleanup(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        if self._temp is not None:
            Path(self._temp).unlink(missing_ok=True)
            self._temp = None
