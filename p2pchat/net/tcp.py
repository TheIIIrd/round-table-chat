"""TCP-бэкенд: прямое соединение с пробросом порта.

Простейший из транспортов и потому первый. UDP с обходом NAT добавится
седьмым этапом отдельной реализацией того же интерфейса ``Link``.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable

from .framing import MAX_FRAME, FrameError, read_frame, write_frame
from .link import Link, LinkClosed

CONNECT_TIMEOUT = 15.0


class TcpLink(Link):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._closed = False
        _disable_nagle(writer)

    @classmethod
    async def connect(
        cls, host: str, port: int, timeout: float = CONNECT_TIMEOUT
    ) -> "TcpLink":
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise LinkClosed(f"не удалось подключиться к {host}:{port}: {exc}") from exc
        return cls(reader, writer)

    @property
    def description(self) -> str:
        try:
            host, port, *_ = self._writer.get_extra_info("peername")
            return f"{host}:{port}"
        except (TypeError, ValueError):
            return "tcp"

    async def send_frame(self, payload: bytes) -> None:
        if self._closed:
            raise LinkClosed("канал закрыт")
        try:
            await write_frame(self._writer, payload, MAX_FRAME)
        except (OSError, ConnectionResetError) as exc:
            raise LinkClosed(f"обрыв при отправке: {exc}") from exc

    async def recv_frame(self) -> bytes:
        if self._closed:
            raise LinkClosed("канал закрыт")
        try:
            return await read_frame(self._reader, MAX_FRAME)
        except asyncio.IncompleteReadError as exc:
            raise LinkClosed("пир закрыл соединение") from exc
        except (OSError, ConnectionResetError) as exc:
            raise LinkClosed(f"обрыв при чтении: {exc}") from exc
        except FrameError as exc:
            # Мусор в потоке — соединение дальше бессмысленно.
            await self.close()
            raise LinkClosed(f"некорректный кадр: {exc}") from exc

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (OSError, ConnectionResetError):
            pass


async def serve(
    host: str,
    port: int,
    handler: Callable[[TcpLink], Awaitable[None]],
) -> asyncio.Server:
    """Поднимает слушающий сокет; ``handler`` вызывается на каждое соединение."""

    async def _on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        link = TcpLink(reader, writer)
        try:
            await handler(link)
        except LinkClosed:
            pass
        finally:
            await link.close()

    return await asyncio.start_server(_on_client, host, port)


def _disable_nagle(writer: asyncio.StreamWriter) -> None:
    """Чат — это мелкие сообщения; алгоритм Нейгла добавил бы им задержку."""
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
