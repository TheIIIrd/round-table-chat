"""Вспомогательные обёртки для тестов.

Раньше возможность испортить кадр была крючком ``on_send`` внутри
``MemoryLink``. Тестовому шву не место в рабочем классе, поэтому вмешательство
в трафик вынесено сюда — обычной обёрткой над ``Link``.
"""

from __future__ import annotations

from collections.abc import Callable

from p2pchat.net.link import Link


class TamperLink(Link):
    """Пропускает кадры через функцию. ``None`` из неё означает потерю кадра."""

    def __init__(self, inner: Link) -> None:
        self._inner = inner
        self.transform: Callable[[bytes], bytes | None] | None = None
        self.sent: list[bytes] = []

    async def send_frame(self, payload: bytes) -> None:
        self.sent.append(payload)
        if self.transform is not None:
            transformed = self.transform(payload)
            if transformed is None:
                return
            payload = transformed
        await self._inner.send_frame(payload)

    async def recv_frame(self) -> bytes:
        return await self._inner.recv_frame()

    async def close(self) -> None:
        await self._inner.close()

    async def inject(self, payload: bytes) -> None:
        """Отправляет кадр в обход преобразования — для проверок на повтор."""
        await self._inner.send_frame(payload)


def flip_byte(index: int) -> Callable[[bytes], bytes]:
    def transform(frame: bytes) -> bytes:
        body = bytearray(frame)
        body[index] ^= 0x01
        return bytes(body)

    return transform


def replace_kind(kind: int) -> Callable[[bytes], bytes]:
    def transform(frame: bytes) -> bytes:
        return bytes([kind]) + frame[1:]

    return transform


def drop_all(_: bytes) -> None:
    return None
