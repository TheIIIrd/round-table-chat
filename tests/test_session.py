"""Тесты защищённой сессии поверх Link."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

import asyncio

import pytest

from p2pchat.crypto import primitives as p
from p2pchat.crypto.identity import Identity
from p2pchat.net.link import LinkClosed, MemoryLink
from p2pchat.proto import session as sess
from tests.helpers import TamperLink, drop_all, flip_byte, replace_kind
from p2pchat.proto.session import (
    KIND_DATA,
    KIND_REKEY_REQUEST,
    Session,
    SessionError,
    build_prologue,
)


async def make_pair(
    prologue_a: bytes = b"", prologue_b: bytes = b"", payloads=(b"a", b"b")
):
    raw_a, link_b = MemoryLink.pair()
    link_a = TamperLink(raw_a)
    a, b = await asyncio.gather(
        Session.initiate(link_a, Identity.generate(), prologue=prologue_a, payload=payloads[0]),
        Session.accept(link_b, Identity.generate(), prologue=prologue_b, payload=payloads[1]),
    )
    return a, b, link_a, link_b


async def _shutdown(*sessions: Session) -> None:
    for s in sessions:
        await s.close()


def test_handshake_over_link_and_sas_match():
    async def scenario():
        pro = build_prologue(mode="direct")
        a, b, _, _ = await make_pair(pro, pro, (b"alice", b"bob"))
        assert a.sas == b.sas
        assert a.peer_payload == b"bob" and b.peer_payload == b"alice"
        assert a.remote_static != b.remote_static
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_prologue_mismatch_fails_handshake():
    async def scenario():
        link_a, link_b = MemoryLink.pair()
        with pytest.raises(p.InvalidTag):
            await asyncio.gather(
                Session.initiate(
                    link_a, Identity.generate(), prologue=build_prologue(group_id=b"A")
                ),
                Session.accept(
                    link_b, Identity.generate(), prologue=build_prologue(group_id=b"B")
                ),
            )

    asyncio.run(scenario())


def test_messages_flow_both_ways():
    async def scenario():
        a, b, _, _ = await make_pair()
        for i in range(50):
            await a.send(f"от A {i}".encode())
            assert await b.receive() == f"от A {i}".encode()
            await b.send(f"от B {i}".encode())
            assert await a.receive() == f"от B {i}".encode()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_rekey_changes_keys_and_keeps_channel_alive():
    async def scenario():
        a, b, _, _ = await make_pair()
        assert a.rekey_count == 0

        await a.rekey()
        assert a.rekey_count == 1 and b.rekey_count == 1

        await a.send("после ротации".encode())
        assert await b.receive() == "после ротации".encode()
        await b.send("и обратно".encode())
        assert await a.receive() == "и обратно".encode()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_rekey_advances_chaining_key():
    """Каждая ротация продолжает цепочку, а не начинает новую."""

    async def scenario():
        a, b, _, _ = await make_pair()
        for round_number in range(1, 6):
            await a.rekey()
            assert a.rekey_count == round_number and b.rekey_count == round_number
            await a.send(f"эпоха {round_number}".encode())
            assert await b.receive() == f"эпоха {round_number}".encode()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_traffic_before_rekey_cannot_be_replayed_after():
    async def scenario():
        a, b, link_a, _ = await make_pair()
        await a.send("старое сообщение".encode())
        assert await b.receive() == "старое сообщение".encode()
        captured = link_a.sent[-1]

        await a.rekey()
        await link_a.inject(captured)  # тот же кадр, новая эпоха ключей
        with pytest.raises(p.InvalidTag):
            await b.receive()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_responder_asks_and_initiator_performs_rekey():
    async def scenario():
        a, b, _, _ = await make_pair()
        await b.rekey()  # отвечающий только просит
        await asyncio.sleep(0)  # даём читателю обработать REKEY_REQUEST
        assert a.rekey_count == 0

        await a.send("триггер".encode())  # ротация случится перед отправкой
        assert await b.receive() == "триггер".encode()
        assert a.rekey_count == 1 and b.rekey_count == 1
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_automatic_rekey_by_message_count(monkeypatch=None):
    async def scenario():
        original = sess.REKEY_AFTER_MESSAGES
        sess.REKEY_AFTER_MESSAGES = 10
        try:
            a, b, _, _ = await make_pair()
            for i in range(25):
                await a.send(f"msg {i}".encode())
                assert await b.receive() == f"msg {i}".encode()
            assert a.rekey_count == 2 and b.rekey_count == 2
            await _shutdown(a, b)
        finally:
            sess.REKEY_AFTER_MESSAGES = original

    asyncio.run(scenario())


def test_tampered_frame_is_reported_to_receiver():
    async def scenario():
        a, b, link_a, _ = await make_pair()

        link_a.transform = flip_byte(3)
        await a.send("важное".encode())
        with pytest.raises(p.InvalidTag):
            await b.receive()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_kind_byte_is_bound_to_ciphertext():
    """Подмена типа кадра ломает тег: заголовок идёт в associated data."""

    async def scenario():
        a, b, link_a, _ = await make_pair()
        link_a.transform = replace_kind(KIND_REKEY_REQUEST)
        await a.send("данные под видом служебного кадра".encode())
        with pytest.raises(p.InvalidTag):
            await b.receive()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_dropped_frame_breaks_the_channel():
    """Пропуск сообщения обнаруживается: счётчики сторон разъезжаются."""

    async def scenario():
        a, b, link_a, _ = await make_pair()
        link_a.transform = drop_all  # кадр не доходит
        await a.send("потеряно".encode())
        link_a.transform = None
        await a.send("следующее".encode())
        with pytest.raises(p.InvalidTag):
            await b.receive()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_unknown_kind_rejected():
    async def scenario():
        a, b, link_a, _ = await make_pair()
        link_a.transform = replace_kind(99)
        await a.send(b"x")
        with pytest.raises((SessionError, p.InvalidTag)):
            await b.receive()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_oversized_payload_refused_locally():
    async def scenario():
        a, b, _, _ = await make_pair()
        with pytest.raises(SessionError):
            await a.send(b"x" * (sess.MAX_PLAINTEXT + 1))
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_close_wakes_up_receiver():
    async def scenario():
        a, b, _, _ = await make_pair()
        await a.close()
        with pytest.raises(LinkClosed):
            await b.receive()
        await b.close()

    asyncio.run(scenario())


def test_send_after_close_refused():
    async def scenario():
        a, b, _, _ = await make_pair()
        await a.close()
        with pytest.raises(LinkClosed):
            await a.send("поздно".encode())
        await b.close()

    asyncio.run(scenario())


def test_error_is_sticky_across_receives():
    """Ошибка канала должна подниматься при каждом вызове, а не один раз."""

    async def scenario():
        a, b, _, _ = await make_pair()
        await a.close()
        for _ in range(3):
            with pytest.raises(LinkClosed):
                await b.receive()
        await b.close()

    asyncio.run(scenario())


def test_inbox_is_bounded():
    """Неограниченная очередь входящих была бы отказом в обслуживании."""

    async def scenario():
        a, b, _, _ = await make_pair()
        for i in range(sess.INBOX_LIMIT + 20):
            await a.send(f"{i}".encode())
        await asyncio.sleep(0)
        assert b._inbox.qsize() <= sess.INBOX_LIMIT
        for i in range(20):
            assert await b.receive() == f"{i}".encode()
        await _shutdown(a, b)

    asyncio.run(scenario())


def test_buffered_messages_survive_close():
    """Уже полученные сообщения читаются, и лишь потом приходит ошибка."""

    async def scenario():
        a, b, _, _ = await make_pair()
        await a.send(b"first")
        await a.send(b"second")
        await asyncio.sleep(0)
        await a.close()
        assert await b.receive() == b"first"
        assert await b.receive() == b"second"
        with pytest.raises(LinkClosed):
            await b.receive()
        await b.close()

    asyncio.run(scenario())
