"""Тесты транспортного слоя: кадрирование и TCP."""

from __future__ import annotations

import asyncio

import pytest

from p2pchat.crypto.identity import Identity
from p2pchat.net import framing
from p2pchat.net.framing import FrameError, read_frame, write_frame
from p2pchat.net.link import LinkClosed, MemoryLink
from p2pchat.net.tcp import TcpLink, serve
from p2pchat.proto.session import Session, build_prologue


def test_frame_roundtrip_preserves_boundaries():
    async def scenario():
        reader = asyncio.StreamReader()
        writer_transport = _CollectingWriter()
        for payload in (b"a", b"bb", b"c" * 1000):
            await write_frame(writer_transport, payload)
        reader.feed_data(writer_transport.data)
        reader.feed_eof()
        assert await read_frame(reader) == b"a"
        assert await read_frame(reader) == b"bb"
        assert await read_frame(reader) == b"c" * 1000

    asyncio.run(scenario())


def test_oversized_frame_rejected_before_allocation():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data((framing.MAX_FRAME + 1).to_bytes(4, "big"))
        reader.feed_eof()
        with pytest.raises(FrameError):
            await read_frame(reader)

    asyncio.run(scenario())


def test_zero_length_frame_rejected():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data((0).to_bytes(4, "big"))
        reader.feed_eof()
        with pytest.raises(FrameError):
            await read_frame(reader)

    asyncio.run(scenario())


def test_truncated_frame_raises():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data((10).to_bytes(4, "big") + b"only4")
        reader.feed_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await read_frame(reader)

    asyncio.run(scenario())


def test_memory_link_close_unblocks_peer():
    async def scenario():
        a, b = MemoryLink.pair()
        await a.close()
        with pytest.raises(LinkClosed):
            await b.recv_frame()

    asyncio.run(scenario())


def test_session_over_real_tcp():
    """Полный путь: сокет, кадрирование, хендшейк, обмен, ротация."""

    async def scenario():
        server_identity = Identity.generate("server")
        client_identity = Identity.generate("client")
        prologue = build_prologue()
        done = asyncio.Event()
        result: dict = {}

        async def handler(link: TcpLink) -> None:
            session = await Session.accept(
                link, server_identity, prologue=prologue, payload=b"server"
            )
            result["sas"] = session.sas
            result["peer"] = session.remote_static
            try:
                while True:
                    await session.send("эхо: ".encode() + await session.receive())
            except (LinkClosed, asyncio.CancelledError):
                pass
            finally:
                await session.close()
                done.set()

        server = await serve("127.0.0.1", 0, handler)
        port = server.sockets[0].getsockname()[1]

        link = await TcpLink.connect("127.0.0.1", port)
        client = await Session.initiate(
            link, client_identity, prologue=prologue, payload=b"client"
        )

        assert client.peer_payload == b"server"
        assert client.remote_static == server_identity.public

        await client.send("привет по сети".encode())
        assert await client.receive() == "эхо: привет по сети".encode()

        await client.rekey()
        await client.send("после ротации".encode())
        assert await client.receive() == "эхо: после ротации".encode()

        assert result["sas"] == client.sas
        assert result["peer"] == client_identity.public

        await client.close()
        await asyncio.wait_for(done.wait(), 5)
        server.close()
        await server.wait_closed()

    asyncio.run(scenario())


def test_tcp_connect_refused():
    async def scenario():
        with pytest.raises(LinkClosed):
            await TcpLink.connect("127.0.0.1", 1, timeout=2)

    asyncio.run(scenario())


class _CollectingWriter:
    """Заглушка StreamWriter: собирает байты вместо отправки в сокет."""

    def __init__(self) -> None:
        self.data = b""

    def write(self, chunk: bytes) -> None:
        self.data += chunk

    async def drain(self) -> None:
        return None
