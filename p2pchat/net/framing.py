"""Кадрирование байтового потока.

TCP не сохраняет границы сообщений, поэтому кадр = ``uint32`` длины (big-endian)
плюс тело. Лимит длины обязателен и проверяется ДО чтения тела: без него
четыре байта от кого угодно заставят нас выделить четыре гигабайта.
"""

from __future__ import annotations

import asyncio

MAX_FRAME = 64 * 1024
LENGTH_PREFIX = 4


class FrameError(Exception):
    """Кадр не соответствует формату: нулевая длина, превышен лимит, обрыв."""


async def read_frame(reader: asyncio.StreamReader, max_frame: int = MAX_FRAME) -> bytes:
    header = await reader.readexactly(LENGTH_PREFIX)
    size = int.from_bytes(header, "big")
    if size == 0:
        raise FrameError("кадр нулевой длины")
    if size > max_frame:
        raise FrameError(f"кадр {size} байт превышает лимит {max_frame}")
    return await reader.readexactly(size)


async def write_frame(
    writer: asyncio.StreamWriter, payload: bytes, max_frame: int = MAX_FRAME
) -> None:
    if not payload:
        raise FrameError("попытка отправить пустой кадр")
    if len(payload) > max_frame:
        raise FrameError(f"кадр {len(payload)} байт превышает лимит {max_frame}")
    writer.write(len(payload).to_bytes(LENGTH_PREFIX, "big") + payload)
    await writer.drain()
