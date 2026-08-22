"""Тесты группового меша поверх реальных сокетов."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access,import-outside-toplevel

from __future__ import annotations

import asyncio
import time

import pytest

from p2pchat.crypto.identity import Identity
from p2pchat.proto import events as ev
from p2pchat.proto.mesh import Mesh
from p2pchat.proto.roster import Member, Roster, RosterError
from p2pchat.proto.trust import TrustStore
from tests.conftest import (
    build_group,
    drain,
    run_async,
    wait_connected,
    wait_for,
    wait_for_text,
)







def test_group_of_three_connects_fully():
    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob", "carol"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 2)
            assert meshes["alice"].network.peers == ["bob", "carol"]
            assert meshes["carol"].network.peers == ["alice", "bob"]
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


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

    run_async(scenario)


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

    run_async(scenario)


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
            host, port = meshes["alice"].network.listen
            await intruder.network.connect_to(host, port)
            alert = await wait_for(meshes["alice"], ev.Alert)
            assert "ростере" in alert.text
            assert meshes["alice"].network.peers == []  # внутрь чужак не попал
            # А он сам узнаёт о закрытии чуть позже — соединение рвёт Алиса.
            await wait_for(intruder, ev.PeerDisconnected)
            assert intruder.network.peers == []
        finally:
            await intruder.stop()
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


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

    run_async(scenario)


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

    run_async(scenario)


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

    run_async(scenario)


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
            live = alice.network._connections[bob.identity.public].session

            # Второе соединение к тому же пиру — как при гонке дозвонов.
            host, port = alice.network.listen
            from p2pchat.net.tcp import TcpLink
            from p2pchat.proto.session import Session

            link = await TcpLink.connect(host, port)
            duplicate = await Session.initiate(
                link, bob.identity, prologue=bob.network.prologue, payload=b"bob"
            )
            await asyncio.sleep(0.2)
            await duplicate.close()
            await asyncio.sleep(0.3)

            assert alice.network.peers == ["bob"], "живое соединение не должно исчезать"
            assert alice.network._connections[bob.identity.public].session is live
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


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
                for event in drain(meshes["alice"])
                if isinstance(event, ev.PeerDisconnected)
            ]
            assert extra == []
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)



# --- регрессии из самостоятельного разбора ---------------------------------------


def test_empty_id_does_not_accept_a_random_file():
    """`/accept` без аргумента принимал первое попавшееся предложение.

    Причина простая и оттого неприятная: `"abc".startswith("")` — истина.
    Принять не тот файл по опечатке — это ровно то, чего чат делать не должен.
    """

    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)

            source = tmp_path / "секрет.bin"
            source.write_bytes(b"S" * 4000)
            await meshes["alice"].offer_file("bob", source)
            offer = await wait_for(meshes["bob"], ev.FileOffered)

            await meshes["bob"].respond_to_offer("", accept=True)
            await wait_for_text(meshes["bob"], "укажите идентификатор")

            downloads = tmp_path / "bob-downloads"
            assert not downloads.exists() or not list(downloads.iterdir())

            # По точному идентификатору всё работает.
            await meshes["bob"].respond_to_offer(offer.transfer_id, accept=True)
            done = await wait_for(meshes["bob"], ev.FileFinished)
            assert done.path.read_bytes() == source.read_bytes()
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_ambiguous_offer_id_is_refused():
    async def scenario(tmp_path):
        from p2pchat.proto.files import IncomingTransfer, encode_offer

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        bob = meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            owner = meshes["alice"].identity.public
            for suffix in (b"\x11", b"\x22"):
                body = encode_offer(b"\xaa" * 15 + suffix, 100, b"\x01" * 32, "f.bin")
                transfer = IncomingTransfer.from_offer(body, tmp_path / "dl")
                bob._incoming[transfer.transfer_id] = _incoming_entry(owner, transfer)

            await bob.respond_to_offer("aaaa", accept=True)
            await wait_for_text(bob, "подходит несколько")
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_event_queue_is_bounded():
    """Ограничение в сессии не значило ничего, пока очередь событий была без предела."""
    from p2pchat.proto.mesh import EVENT_QUEUE_LIMIT

    async def scenario(tmp_path):
        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            assert meshes["alice"].events.maxsize == EVENT_QUEUE_LIMIT
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_offer_flood_is_capped():
    async def scenario(tmp_path):
        from p2pchat.proto.mesh import MAX_PENDING_OFFERS_PER_PEER

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            for index in range(MAX_PENDING_OFFERS_PER_PEER + 3):
                source = tmp_path / f"file{index}.bin"
                source.write_bytes(b"x" * 100)
                await meshes["alice"].offer_file("bob", source)
            await asyncio.sleep(0.4)
            assert len(meshes["bob"]._incoming) <= MAX_PENDING_OFFERS_PER_PEER
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_abandoned_transfer_is_swept():
    """Принятая, но брошенная передача не должна оставлять .part навсегда."""

    async def scenario(tmp_path):
        from p2pchat.proto.mesh import TRANSFER_IDLE_TIMEOUT

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        bob = meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            source = tmp_path / "big.bin"
            source.write_bytes(b"B" * 200_000)
            await meshes["alice"].offer_file("bob", source)
            offer = await wait_for(bob, ev.FileOffered)
            await bob.respond_to_offer(offer.transfer_id, accept=True)
            await asyncio.sleep(0.2)

            # Делаем вид, что прошло много времени без единого куска.
            for entry in bob._incoming.values():
                entry.touched -= TRANSFER_IDLE_TIMEOUT * 2
            await bob.sweep(__import__("time").monotonic())

            assert bob._incoming == {}
            downloads = tmp_path / "bob-downloads"
            assert not list(downloads.glob(".*.part"))
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def _incoming_entry(owner, transfer):
    import time as _time

    from p2pchat.proto.mesh import _Incoming

    return _Incoming(owner=owner, transfer=transfer, touched=_time.monotonic())


def test_send_timeout_outlives_rekey():
    """Порядок величин между слоями, который легко сломать незаметно.

    Ротация ключей запускается внутри session.send(). Если внешний таймаут
    отправки меньше, чем таймаут ротации, исправный пир будет отключён посреди
    штатной смены ключей.
    """
    from p2pchat.proto.network import SEND_TIMEOUT
    from p2pchat.proto.session import HANDSHAKE_TIMEOUT, REKEY_TIMEOUT

    assert SEND_TIMEOUT > REKEY_TIMEOUT
    assert HANDSHAKE_TIMEOUT > REKEY_TIMEOUT


def test_sender_does_not_accumulate_unanswered_offers():
    """Предложения копились у отправителя вечно: уборщик знал только про входящие."""

    async def scenario(tmp_path):
        from p2pchat.proto.mesh import MAX_OUTGOING_OFFERS_PER_PEER

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        alice, bob = meshes["alice"], meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)

            for index in range(12):
                source = tmp_path / f"f{index}.bin"
                source.write_bytes(b"x" * 100)
                await alice.offer_file("bob", source)
            await asyncio.sleep(0.5)

            assert len(alice._outgoing) <= MAX_OUTGOING_OFFERS_PER_PEER
            assert len(bob._incoming) <= 3

            for item in alice._outgoing.values():
                item.touched -= 10_000
            await alice.sweep(time.monotonic())
            assert alice._outgoing == {}
            failure = await wait_for(alice, ev.FileFailed)
            assert "не ответил" in failure.reason
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_excess_offer_is_declined_not_ignored():
    """Молчание оставило бы отправителя ждать ответа, которого не будет.

    Предел на исходящие предложения здесь мешает: он не даёт дойти до предела
    входящих. Поэтому предложения отправляются в обход него, напрямую в сеть —
    проверяется именно поведение получателя.
    """

    async def scenario(tmp_path):
        from p2pchat.proto.envelope import TYPE_FILE_OFFER, make
        from p2pchat.proto.files import encode_offer
        from p2pchat.proto.mesh import MAX_PENDING_OFFERS_PER_PEER

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        alice, bob = meshes["alice"], meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            target = bob.identity.public

            declined = []
            for index in range(MAX_PENDING_OFFERS_PER_PEER + 2):
                body = encode_offer(
                    bytes([index]) + b"\x00" * 15, 1000, b"\x01" * 32, f"f{index}.bin"
                )
                await alice.network.send(target, make(TYPE_FILE_OFFER, body).encode())
                await asyncio.sleep(0.1)

            await asyncio.sleep(0.3)
            assert len(bob._incoming) == MAX_PENDING_OFFERS_PER_PEER

            # Лишние предложения получили явный отказ, а не молчание.
            declined = [
                event
                for event in drain(bob)
                if isinstance(event, ev.Notice) and "отклонил" in event.text
            ]
            assert declined
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


async def _synthetic_incoming(receiver, sender_public, tmp_path, size=100_000):
    """Заводит принимаемую передачу без гонки с настоящей отправкой.

    Настоящий файл на сто килобайт успевает дойти за миллисекунды, и проверять
    состояние «во время передачи» на нём — значит писать тест, который иногда
    проходит.
    """
    from p2pchat.proto.files import IncomingTransfer, encode_offer

    body = encode_offer(b"\xcd" * 16, size, b"\x01" * 32, "big.bin")
    transfer = IncomingTransfer.from_offer(body, tmp_path / "dl")
    receiver._incoming[transfer.transfer_id] = _incoming_entry(sender_public, transfer)
    await receiver._respond(transfer.transfer_id, accept=True)
    return transfer.transfer_id


def test_foreign_finish_does_not_steal_a_transfer():
    """Проверка владельца должна идти ДО снятия записи, иначе .part осиротеет."""

    async def scenario(tmp_path):
        from p2pchat.proto.envelope import TYPE_FILE_DONE, make
        from p2pchat.proto.files import TransferError

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob", "carol"])
        bob = meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 2)
            transfer_id = await _synthetic_incoming(
                bob, meshes["alice"].identity.public, tmp_path
            )

            outsider = bob.network.member_by_nick("carol")
            try:
                await bob._on_message(outsider, make(TYPE_FILE_DONE, transfer_id).encode())
            except TransferError:
                pass

            assert transfer_id in bob._incoming, "чужое завершение выбило передачу"
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)


def test_broken_chunk_closes_transfer_at_once():
    async def scenario(tmp_path):
        from p2pchat.proto.envelope import TYPE_FILE_CHUNK, make
        from p2pchat.proto.files import encode_chunk

        meshes, _, _ = await build_group(tmp_path, ["alice", "bob"])
        bob = meshes["bob"]
        try:
            for mesh in meshes.values():
                await wait_connected(mesh, 1)
            alice_public = meshes["alice"].identity.public
            transfer_id = await _synthetic_incoming(bob, alice_public, tmp_path)

            member = bob.network.member_by_nick("alice")
            body = encode_chunk(transfer_id, 999, b"junk")  # заведомо не тот номер
            await bob._on_message(member, make(TYPE_FILE_CHUNK, body).encode())

            assert transfer_id not in bob._incoming
            assert not list((tmp_path / "dl").glob(".*.part"))
        finally:
            for mesh in meshes.values():
                await mesh.stop()

    run_async(scenario)

