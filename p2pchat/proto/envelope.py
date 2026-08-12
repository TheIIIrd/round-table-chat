"""Конверт прикладного сообщения.

Формат намеренно бинарный и фиксированный::

    тип(1) | lamport(8, BE) | время отправителя, мс(8, BE) | тело

В концепции обсуждался CBOR, но он потребовал бы внешней зависимости
(``cbor2`` не входит в стандартную библиотеку), а JSON заставил бы кодировать
куски файлов в base64 — плюс треть к объёму на каждом чанке. Свой формат из
семнадцати байт заголовка проще, быстрее и не добавляет зависимостей.

Часы Лампорта дают причинный порядок без общего сервера времени. Настенное
время отправителя передаётся, но только для показа: часы у участников
расходятся, и доверять им в упорядочивании нельзя.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

TYPE_TEXT = 1
TYPE_PRESENCE = 2
TYPE_FILE_OFFER = 3
TYPE_FILE_ACCEPT = 4
TYPE_FILE_DECLINE = 5
TYPE_FILE_CHUNK = 6
TYPE_FILE_DONE = 7

KNOWN_TYPES = frozenset(
    {
        TYPE_TEXT,
        TYPE_PRESENCE,
        TYPE_FILE_OFFER,
        TYPE_FILE_ACCEPT,
        TYPE_FILE_DECLINE,
        TYPE_FILE_CHUNK,
        TYPE_FILE_DONE,
    }
)

HEADER_LEN = 1 + 8 + 8


class EnvelopeError(Exception):
    """Конверт не разбирается: обрыв, неизвестный тип."""


@dataclass(frozen=True)
class Envelope:
    type: int
    lamport: int
    sent_at_ms: int
    body: bytes

    def encode(self) -> bytes:
        return (
            bytes([self.type])
            + self.lamport.to_bytes(8, "big")
            + self.sent_at_ms.to_bytes(8, "big")
            + self.body
        )

    @classmethod
    def decode(cls, raw: bytes) -> "Envelope":
        if len(raw) < HEADER_LEN:
            raise EnvelopeError("конверт короче заголовка")
        kind = raw[0]
        if kind not in KNOWN_TYPES:
            raise EnvelopeError(f"неизвестный тип сообщения: {kind}")
        return cls(
            type=kind,
            lamport=int.from_bytes(raw[1:9], "big"),
            sent_at_ms=int.from_bytes(raw[9:17], "big"),
            body=raw[HEADER_LEN:],
        )


class LamportClock:
    """Логические часы: причинный порядок без синхронизации времени."""

    def __init__(self) -> None:
        self.value = 0

    def tick(self) -> int:
        self.value += 1
        return self.value

    def observe(self, remote: int) -> int:
        self.value = max(self.value, remote) + 1
        return self.value


def now_ms() -> int:
    return int(time.time() * 1000)


def make(kind: int, clock: LamportClock, body: bytes = b"") -> Envelope:
    return Envelope(type=kind, lamport=clock.tick(), sent_at_ms=now_ms(), body=body)
