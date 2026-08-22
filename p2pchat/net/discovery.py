"""Обнаружение участников в локальной сети.

Периодический UDP-бикон в мультикаст-группу: «я такой-то ключ, слушаю такой-то
порт». Услышали знакомый по ростеру ключ — узнали адрес и соединились.

**Почему бикон не подписан.** Обнаружение здесь не является частью
аутентификации. Ключи участников зафиксированы в ростере и входят в prologue
хендшейка, поэтому подложный адрес приводит ровно к одному последствию —
неудачной попытке соединения. Подписывать подсказку, которую и так проверяет
следующий шаг, значило бы усложнять код без выигрыша.

Что бикон всё же выдаёт: в пределах локального сегмента видно, что участник с
таким-то ключом находится в этой сети. Внутри домашней или офисной сети это
обычно не имеет значения, но включать обнаружение стоит осознанно — отсюда
отдельный флаг, а не поведение по умолчанию.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass

MULTICAST_GROUP = "239.255.77.33"
MULTICAST_PORT = 45333
BEACON_INTERVAL = 2.0
MAGIC = b"P2PB1"
MAX_NICK_LEN = 32
MAX_BEACON_LEN = 256


@dataclass(frozen=True)
class Beacon:
    group_id: bytes
    public: bytes
    port: int
    nick: str

    def encode(self) -> bytes:
        nick = self.nick.encode("utf-8")[:MAX_NICK_LEN]
        return (
            MAGIC
            + bytes([len(self.group_id)])
            + self.group_id
            + self.public
            + self.port.to_bytes(2, "big")
            + bytes([len(nick)])
            + nick
        )

    @classmethod
    def decode(cls, raw: bytes) -> "Beacon | None":
        """Возвращает ``None`` на любом мусоре: в мультикасте его хватает."""
        if len(raw) > MAX_BEACON_LEN or not raw.startswith(MAGIC):
            return None
        try:
            offset = len(MAGIC)
            group_len = raw[offset]
            offset += 1
            group_id = raw[offset : offset + group_len]
            offset += group_len
            public = raw[offset : offset + 32]
            offset += 32
            if len(public) != 32:
                return None
            port = int.from_bytes(raw[offset : offset + 2], "big")
            offset += 2
            nick_len = raw[offset]
            offset += 1
            nick = raw[offset : offset + nick_len].decode("utf-8")
            offset += nick_len
        except (IndexError, UnicodeDecodeError):
            return None
        if offset != len(raw) or not 1 <= port <= 65535:
            return None
        return cls(group_id=group_id, public=public, port=port, nick=nick)


OnPeer = Callable[[bytes, str, int, str], None]


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, discovery: "Discovery") -> None:
        self._discovery = discovery

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._discovery.handle_datagram(data, addr[0])

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass


class Discovery:
    """Рассылает свой бикон и слушает чужие."""

    def __init__(
        self,
        *,
        group_id: bytes,
        public: bytes,
        nick: str,
        port: int,
        on_peer: OnPeer,
        multicast_group: str = MULTICAST_GROUP,
        multicast_port: int = MULTICAST_PORT,
        interval: float = BEACON_INTERVAL,
    ) -> None:
        self.beacon = Beacon(group_id=group_id, public=public, port=port, nick=nick)
        self.on_peer = on_peer
        self.multicast_group = multicast_group
        self.multicast_port = multicast_port
        self.interval = interval
        self._transport: asyncio.DatagramTransport | None = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with contextlib.suppress(AttributeError, OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", self.multicast_port))
        membership = struct.pack(
            "4s4s", socket.inet_aton(self.multicast_group), socket.inet_aton("0.0.0.0")
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)  # не за пределы сегмента
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(self), sock=sock)
        self._transport = transport  # type: ignore[assignment]
        self._task = asyncio.create_task(self._announce_loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def handle_datagram(self, data: bytes, host: str) -> None:
        beacon = Beacon.decode(data)
        if beacon is None:
            return
        if beacon.public == self.beacon.public:
            return  # собственное эхо
        if beacon.group_id != self.beacon.group_id:
            return  # соседи из другой группы
        self.on_peer(beacon.public, host, beacon.port, beacon.nick)

    async def _announce_loop(self) -> None:
        payload = self.beacon.encode()
        while True:
            if self._transport is not None:
                with contextlib.suppress(OSError):
                    self._transport.sendto(payload, (self.multicast_group, self.multicast_port))
            await asyncio.sleep(self.interval)
