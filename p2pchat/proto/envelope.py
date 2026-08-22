"""Конверт прикладного сообщения.

Формат намеренно бинарный и фиксированный::

    тип(1) | время отправителя, мс(8, BE) | тело

В концепции обсуждался CBOR, но он потребовал бы внешней зависимости
(``cbor2`` не входит в стандартную библиотеку), а JSON заставил бы кодировать
куски файлов в base64 — плюс треть к объёму на каждом чанке. Свой формат из
семнадцати байт заголовка проще, быстрее и не добавляет зависимостей.

Настенное время отправителя передаётся, но только для показа: часы у участников
расходятся, и доверять им в упорядочивании нельзя.

Здесь были часы Лампорта. Они честно считались и ехали в каждом сообщении — и
нигде не использовались: получатель показывал реплики в порядке прихода. Поле,
которое никто не читает, хуже отсутствующего: оно создаёт впечатление, что
причинный порядок обеспечен. В попарном меше сообщения от одного собеседника и
так приходят по порядку, а настоящий межпировой порядок потребовал бы буфера
переупорядочивания и задержки — это отдельная задача, а не поле в заголовке.
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
TYPE_ADDRESS = 8

KNOWN_TYPES = frozenset(
    {
        TYPE_TEXT,
        TYPE_PRESENCE,
        TYPE_FILE_OFFER,
        TYPE_FILE_ACCEPT,
        TYPE_FILE_DECLINE,
        TYPE_FILE_CHUNK,
        TYPE_FILE_DONE,
        TYPE_ADDRESS,
    }
)

HEADER_LEN = 1 + 8


class EnvelopeError(Exception):
    """Конверт не разбирается: обрыв, неизвестный тип."""


@dataclass(frozen=True)
class Envelope:
    type: int
    sent_at_ms: int
    body: bytes

    def encode(self) -> bytes:
        return bytes([self.type]) + self.sent_at_ms.to_bytes(8, "big") + self.body

    @classmethod
    def decode(cls, raw: bytes) -> "Envelope":
        if len(raw) < HEADER_LEN:
            raise EnvelopeError("конверт короче заголовка")
        kind = raw[0]
        if kind not in KNOWN_TYPES:
            raise EnvelopeError(f"неизвестный тип сообщения: {kind}")
        return cls(
            type=kind,
            sent_at_ms=int.from_bytes(raw[1:9], "big"),
            body=raw[HEADER_LEN:],
        )


def now_ms() -> int:
    return int(time.time() * 1000)


def make(kind: int, body: bytes = b"") -> Envelope:
    return Envelope(type=kind, sent_at_ms=now_ms(), body=body)
