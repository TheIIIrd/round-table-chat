"""Общие помощники для тестов.

Появились после того, как `test_bot.py` начал импортировать утилиты из
`test_mesh.py`: поломка одного тестового модуля роняла другой, а помощники жили
не там, где их ищут. Здесь им место.

Имя `conftest.py` выбрано не случайно — pytest подхватывает его сам, поэтому
фикстуры можно будет добавить сюда же, не меняя импорты в тестах.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from pathlib import Path

from p2pchat.crypto.identity import Identity
from p2pchat.proto.mesh import Mesh
from p2pchat.proto.roster import Member, Roster
from p2pchat.proto.trust import TrustStore


def free_ports(count: int) -> list[int]:
    """Занимает и сразу освобождает порты, чтобы получить свободные номера."""
    sockets = []
    ports = []
    for _ in range(count):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        ports.append(probe.getsockname()[1])
        sockets.append(probe)
    for probe in sockets:
        probe.close()
    return ports


async def build_group(tmp_path, nicks: list[str], bots: set[str] = frozenset()):
    """Поднимает группу мешей на локальных портах с общим ростером."""
    ports = free_ports(len(nicks))
    identities = {nick: Identity.generate(nick) for nick in nicks}
    roster = Roster(
        name="test",
        members=tuple(
            Member(
                nick=nick,
                public=identities[nick].public,
                host="127.0.0.1",
                port=port,
                is_bot=nick in bots,
            )
            for nick, port in zip(nicks, ports)
        ),
    )
    meshes = {}
    for nick, port in zip(nicks, ports):
        meshes[nick] = Mesh(
            identities[nick],
            nickname=nick,
            roster=roster,
            trust=TrustStore.load(tmp_path / f"{nick}-known.json"),
            download_dir=tmp_path / f"{nick}-downloads",
            listen=("127.0.0.1", port),
        )
    for mesh in meshes.values():
        await mesh.start()
    return meshes, roster, identities


async def wait_for(mesh: Mesh, kind, timeout: float = 10.0):
    """Ждёт событие нужного типа, пропуская остальные."""

    async def pump():
        while True:
            event = await mesh.events.get()
            if isinstance(event, kind):
                return event

    return await asyncio.wait_for(pump(), timeout)


async def wait_for_text(mesh: Mesh, fragment: str, timeout: float = 10.0):
    """Ждёт событие, в тексте которого есть нужный фрагмент.

    Просто «ждать Notice» мало: в очереди уже лежат служебные уведомления вроде
    «слушаю ...», и тест поймал бы первое из них.
    """

    async def pump():
        while True:
            event = await mesh.events.get()
            if fragment in event.render():
                return event

    return await asyncio.wait_for(pump(), timeout)


async def wait_connected(mesh: Mesh, count: int, timeout: float = 10.0) -> None:
    async def pump():
        while len(mesh.network.peers) < count:
            await asyncio.sleep(0.05)

    await asyncio.wait_for(pump(), timeout)


def drain(mesh: Mesh) -> list:
    collected = []
    while not mesh.events.empty():
        collected.append(mesh.events.get_nowait())
    return collected


def run_async(scenario) -> None:
    """Запускает сценарий во временном каталоге."""
    with tempfile.TemporaryDirectory() as tmp:
        asyncio.run(scenario(Path(tmp)))
