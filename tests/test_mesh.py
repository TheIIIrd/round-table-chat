"""Тесты группового меша поверх реальных сокетов."""

from __future__ import annotations

import asyncio

import pytest

from p2pchat.crypto.identity import Identity
from p2pchat.proto import events as ev
from p2pchat.proto.mesh import Mesh
from p2pchat.proto.roster import Member, Roster, RosterError
from p2pchat.proto.trust import TrustStore


def free_ports(count: int) -> list[int]:
    import socket

    socks = []
    ports = []
    for _ in range(count):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        socks.append(s)
    for s in socks:
        s.close()
    return ports


async def build_group(tmp_path, nicks: list[str], bots: set[str] = frozenset()):
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


async def wait_connected(mesh: Mesh, count: int, timeout: float = 10.0) -> None:
    async def pump():
        while len(mesh.peers) < count:
            await asyncio.sleep(0.05)

    await asyncio.wait_for(pump(), timeout)


def test_group_of_three_connects_fully():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob", "carol"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 2)
            assert meshes["alice"].peers == ["bob", "carol"]
            assert meshes["carol"].peers == ["alice", "bob"]
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_broadcast_reaches_every_member():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob", "carol"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 2)
            await meshes["alice"].broadcast("всем привет")
            for nick in ("bob", "carol"):
                message = await wait_for(meshes[nick], ev.TextMessage)
                assert message.text == "всем привет"
                assert message.nick == "alice"
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_sas_matches_on_both_ends():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            a = await wait_for(meshes["alice"], ev.PeerConnected)
            b = await wait_for(meshes["bob"], ev.PeerConnected)
            assert a.sas == b.sas
            assert a.nick == "bob" and b.nick == "alice"
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_outsider_key_is_rejected():
    """Ключа нет в ростере — соединение не устанавливается."""

    async def scenario(tmp_path):
        meshes, roster, _ = await build_group(tmp_path, ["alice", "bob"])
        outsider = Identity.generate("mallory")
        intruder = Mesh(
            outsider,
            nickname="mallory",
            roster=roster,  # знает ростер, но сам в него не входит
            trust=TrustStore.load(tmp_path / "mallory-known.json"),
            download_dir=tmp_path / "mallory-downloads",
            listen=None,
        )
        try:
            host, port = meshes["alice"].listen
            await intruder.connect_to(host, port)
            alert = await wait_for(meshes["alice"], ev.Alert)
            assert "ростере" in alert.text
            assert meshes["alice"].peers == []  # внутрь чужак не попал
            # А он сам узнаёт о закрытии чуть позже — соединение рвёт Алиса.
            await wait_for(intruder, ev.PeerDisconnected)
            assert intruder.peers == []
        finally:
            await intruder.stop()
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_file_transfer_end_to_end():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)

            payload = b"\x00\xff" * 50_000  # 100 КиБ, несколько чанков
            source = tmp_path / "секрет.bin"
            source.write_bytes(payload)

            await meshes["alice"].offer_file("bob", source)
            offer = await wait_for(meshes["bob"], ev.FileOffered)
            assert offer.name == "секрет.bin" and offer.size == len(payload)

            await meshes["bob"].respond_to_offer(offer.transfer_id, accept=True)
            finished = await wait_for(meshes["bob"], ev.FileFinished)
            assert finished.path.read_bytes() == payload
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_declined_file_is_not_written():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            source = tmp_path / "data.bin"
            source.write_bytes(b"x" * 1000)

            await meshes["alice"].offer_file("bob", source)
            offer = await wait_for(meshes["bob"], ev.FileOffered)
            await meshes["bob"].respond_to_offer(offer.transfer_id, accept=False)

            failure = await wait_for(meshes["alice"], ev.FileFailed)
            assert "отказ" in failure.reason
            downloads = tmp_path / "bob-downloads"
            assert not downloads.exists() or not list(downloads.iterdir())
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_disconnect_is_reported():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            await meshes["bob"].stop()
            gone = await wait_for(meshes["alice"], ev.PeerDisconnected)
            assert gone.nick == "bob"
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_roster_id_depends_on_members():
    a, b, c = (Identity.generate().public for _ in range(3))
    pair = Roster("g", (Member("a", a), Member("b", b)))
    same_pair_other_order = Roster("g", (Member("b", b), Member("a", a)))
    trio = Roster("g", (Member("a", a), Member("b", b), Member("c", c)))

    assert pair.group_id == same_pair_other_order.group_id
    assert pair.group_id != trio.group_id
    assert len(pair.group_id) == 16


def test_roster_rejects_bad_input():
    with pytest.raises(RosterError):
        Roster.from_json({"members": []})
    with pytest.raises(RosterError):
        Roster.from_json({"members": [{"nick": "a", "key": "zz"}]})
    with pytest.raises(RosterError):
        Roster.from_json({"members": [{"nick": "a", "key": "00" * 32, "address": "host"}]})
    key = "11" * 32
    with pytest.raises(RosterError):
        Roster.from_json({"members": [{"nick": "a", "key": key}, {"nick": "a", "key": "22" * 32}]})
    with pytest.raises(RosterError):
        Roster.from_json(
            {"members": [{"nick": f"n{i}", "key": f"{i:02x}" * 32} for i in range(9)]}
        )


def _run(scenario):
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        asyncio.run(scenario(Path(tmp)))


def test_duplicate_connection_does_not_evict_the_live_one():
    """Регрессия: закрытие лишней сессии выносило из таблицы живую.

    Проявлялось в живом чате как «участник исчез из /peers, хотя он на связи»:
    при одновременном дозвоне обе стороны создавали по сессии, лишнюю закрывали,
    а уборка удаляла запись по ключу пира, не проверяя, та ли это сессия.
    """

    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)

            alice, bob = meshes["alice"], meshes["bob"]
            live = alice._connections[bob.identity.public].session

            # Второе соединение к тому же пиру — как при гонке дозвонов.
            host, port = alice.listen
            from p2pchat.net.tcp import TcpLink
            from p2pchat.proto.session import Session

            link = await TcpLink.connect(host, port)
            duplicate = await Session.initiate(
                link, bob.identity, prologue=bob.prologue, payload=b"bob"
            )
            await asyncio.sleep(0.2)
            await duplicate.close()
            await asyncio.sleep(0.3)

            assert alice.peers == ["bob"], "живое соединение не должно исчезать"
            assert alice._connections[bob.identity.public].session is live
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def test_disconnect_reported_once_per_peer():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            await meshes["bob"].stop()
            await wait_for(meshes["alice"], ev.PeerDisconnected)
            await asyncio.sleep(0.3)

            extra = [
                event
                for event in _drain(meshes["alice"])
                if isinstance(event, ev.PeerDisconnected)
            ]
            assert extra == []
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    _run(scenario)


def _drain(mesh):
    collected = []
    while not mesh.events.empty():
        collected.append(mesh.events.get_nowait())
    return collected
