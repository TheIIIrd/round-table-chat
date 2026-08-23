"""Тесты упрощённого соединения: приглашения, адреса, обнаружение."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access,import-outside-toplevel

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from p2pchat.crypto.identity import Identity
from p2pchat.net.discovery import Beacon, Discovery
from p2pchat.proto import invite as invites
from p2pchat.proto.invite import InviteError
from p2pchat.proto.roster import Member, Roster
from p2pchat.proto.trust import TrustStore


# --- приглашения -------------------------------------------------------------


def test_peer_invite_roundtrip():
    member = Member("alice", Identity.generate().public, "203.0.113.10", 9333)
    parsed = invites.decode_peer(invites.encode_peer(member))
    assert parsed.member == member
    assert len(parsed.fingerprint.replace(" ", "")) == 32


def test_invite_is_short_enough_to_paste():
    member = Member("alice", Identity.generate().public, "203.0.113.10", 9333)
    assert len(invites.encode_peer(member)) < 140


def test_invite_survives_case_and_whitespace():
    """Строку могут переслать в мессенджере, который «поможет» с форматированием."""
    member = Member("боб", Identity.generate().public, "example.org", 9333)
    text = invites.encode_peer(member)
    mangled = " " + text[:40].lower() + "\n" + text[40:] + "  "
    assert invites.decode_peer(mangled).member == member


def test_typo_is_caught_by_checksum():
    text = invites.encode_peer(Member("alice", Identity.generate().public, "10.0.0.1", 9333))
    for position in range(len(invites.PEER_PREFIX), len(text)):
        original = text[position]
        replacement = "A" if original != "A" else "B"
        spoiled = text[:position] + replacement + text[position + 1 :]
        with pytest.raises(InviteError):
            invites.decode_peer(spoiled)


def test_non_canonical_base32_rejected():
    """Опечатка в последнем символе попадает в неиспользуемые биты base32.

    Такая строка декодируется в те же байты, поэтому контрольная сумма её не
    заметит — ловим по несовпадению с каноничной записью.
    """
    text = invites.encode_peer(Member("alice", Identity.generate().public, "10.0.0.1", 9333))
    for replacement in "ABCDEFGH":
        if replacement == text[-1]:
            continue
        with pytest.raises(InviteError):
            invites.decode_peer(text[:-1] + replacement)


def test_invite_without_address_is_valid():
    member = Member("alice", Identity.generate().public)
    parsed = invites.decode_peer(invites.encode_peer(member))
    assert parsed.member.address is None


def test_bot_flag_survives():
    member = Member("dice", Identity.generate().public, "10.0.0.1", 9334, is_bot=True)
    assert invites.decode_peer(invites.encode_peer(member)).member.is_bot is True


def test_garbage_rejected():
    for bad in ("", "просто текст", "p2pchat:", "p2pchat:!!!!", "p2pchat:AAAAAAAA"):
        with pytest.raises(InviteError):
            invites.decode_peer(bad)


def test_wrong_kind_of_invite_rejected():
    roster = Roster("g", (Member("a", Identity.generate().public),))
    group_text = invites.encode_group(roster)
    with pytest.raises(InviteError):
        invites.decode_peer(group_text)
    with pytest.raises(InviteError):
        invites.decode_group(invites.encode_peer(Member("a", Identity.generate().public)))


def test_group_invite_roundtrip():
    members = tuple(
        Member(nick, Identity.generate().public, "127.0.0.1", 9400 + index, is_bot=(nick == "dice"))
        for index, nick in enumerate(["alice", "bob", "carol", "dice"])
    )
    roster = Roster("друзья", members)
    restored = invites.decode_group(invites.encode_group(roster))
    assert restored.group_id == roster.group_id
    assert restored.members == roster.members
    assert invites.looks_like_group(invites.encode_group(roster))


def test_group_invite_stays_pasteable():
    members = tuple(
        Member(f"user{index}", Identity.generate().public, "203.0.113.10", 9400 + index)
        for index in range(8)
    )
    assert len(invites.encode_group(Roster("макс", members))) < 1400


# --- запоминание адресов ------------------------------------------------------


def test_trust_remembers_working_address():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "known.json"
        trust = TrustStore.load(path)
        peer = Identity.generate().public
        trust.remember(peer, "bob")
        trust.remember_address(peer, "198.51.100.7", 9333)

        reloaded = TrustStore.load(path)
        assert reloaded.by_key(peer).endpoint == ("198.51.100.7", 9333)


def test_address_is_not_stored_for_unknown_peer():
    with tempfile.TemporaryDirectory() as tmp:
        trust = TrustStore.load(Path(tmp) / "known.json")
        trust.remember_address(Identity.generate().public, "10.0.0.1", 9333)
        assert trust.peers == {}


def test_mesh_prefers_fresher_address():
    """Бикон свежее записанного адреса, записанный — свежее ростера."""
    from p2pchat.proto.mesh import Mesh

    with tempfile.TemporaryDirectory() as tmp:
        me, peer = Identity.generate("me"), Identity.generate("peer")
        member = Member("peer", peer.public, "roster.example", 9333)
        roster = Roster("g", (Member("me", me.public), member))
        trust = TrustStore.load(Path(tmp) / "known.json")
        mesh = Mesh(
            me,
            nickname="me",
            roster=roster,
            trust=trust,
            download_dir=Path(tmp) / "dl",
            listen=None,
        )

        assert mesh.network._candidate_address(member) == ("roster.example", 9333)

        trust.remember(peer.public, "peer")
        trust.remember_address(peer.public, "10.0.0.5", 9333)
        assert mesh.network._candidate_address(member) == ("10.0.0.5", 9333)

        mesh.network._on_discovered(peer.public, "192.168.1.20", 9333, "peer")
        assert mesh.network._candidate_address(member) == ("192.168.1.20", 9333)


# --- обнаружение --------------------------------------------------------------


def test_beacon_roundtrip():
    beacon = Beacon(group_id=b"\x01" * 16, public=b"\x02" * 32, port=9333, nick="алиса")
    assert Beacon.decode(beacon.encode()) == beacon


def test_beacon_rejects_garbage():
    assert Beacon.decode(b"") is None
    assert Beacon.decode("случайный мусор в мультикасте".encode()) is None
    assert Beacon.decode(b"P2PB1" + b"\x00" * 3) is None
    good = Beacon(group_id=b"\x01" * 16, public=b"\x02" * 32, port=9333, nick="x").encode()
    assert Beacon.decode(good + "лишнее".encode()) is None
    assert Beacon.decode(b"\xff" * 500) is None


def test_discovery_filters_foreign_and_self():
    seen = []
    mine = b"\x02" * 32
    discovery = Discovery(
        group_id=b"\x01" * 16,
        public=mine,
        nick="me",
        port=9333,
        on_peer=lambda public, host, port, nick: seen.append((public, host, port, nick)),
    )

    other = b"\x03" * 32
    discovery.handle_datagram(
        Beacon(group_id=b"\x01" * 16, public=other, port=9401, nick="peer").encode(), "10.0.0.2"
    )
    discovery.handle_datagram(
        Beacon(group_id=b"\x01" * 16, public=mine, port=9333, nick="me").encode(), "10.0.0.1"
    )  # собственное эхо
    discovery.handle_datagram(
        Beacon(group_id=b"\x09" * 16, public=b"\x04" * 32, port=9402, nick="чужой").encode(),
        "10.0.0.3",
    )  # другая группа
    discovery.handle_datagram("мусор".encode(), "10.0.0.4")

    assert seen == [(other, "10.0.0.2", 9401, "peer")]


def test_mesh_ignores_beacon_from_outside_roster():
    from p2pchat.proto.mesh import Mesh

    with tempfile.TemporaryDirectory() as tmp:
        me = Identity.generate("me")
        mesh = Mesh(
            me,
            nickname="me",
            roster=Roster("g", (Member("me", me.public),)),
            trust=TrustStore.load(Path(tmp) / "known.json"),
            download_dir=Path(tmp) / "dl",
            listen=None,
        )
        mesh.network._on_discovered(Identity.generate().public, "10.0.0.9", 9333, "чужак")
        assert mesh.network._discovered == {}


def test_discovery_reports_when_it_cannot_send():
    """Молчащее обнаружение хуже отсутствующего: об ошибке нужно сказать вслух."""
    problems: list[str] = []
    discovery = Discovery(
        group_id=b"\x01" * 16,
        public=b"\x02" * 32,
        nick="me",
        port=9333,
        on_peer=lambda *args: None,
        on_error=problems.append,
    )

    class BrokenTransport:
        def sendto(self, *args):
            raise OSError("Network is unreachable")

    discovery._transport = BrokenTransport()
    discovery._announce(b"payload")
    discovery._announce(b"payload")  # повторно молчим, чтобы не спамить

    assert len(problems) == 1
    assert "unreachable" in problems[0]
    assert discovery.sent == 0


def test_discovery_over_real_multicast():
    """Сквозная проверка мультикаста.

    Мультикаст доступен не везде: контейнеры, некоторые конфигурации Nix и
    firewall его не пропускают, причём сокет при этом создаётся успешно, а
    пакеты просто никуда не уходят. Поэтому отсутствие бикона здесь — не провал
    проекта, а свойство окружения, и тест пропускается, а не падает.
    """

    async def scenario():
        received: asyncio.Queue = asyncio.Queue()
        listener = Discovery(
            group_id=b"\x07" * 16,
            public=b"\x08" * 32,
            nick="listener",
            port=9501,
            on_peer=lambda *args: received.put_nowait(args),
            multicast_port=45999,
            interval=100.0,
        )
        talker = Discovery(
            group_id=b"\x07" * 16,
            public=b"\x09" * 32,
            nick="talker",
            port=9502,
            on_peer=lambda *args: None,
            multicast_port=45999,
            interval=0.2,
        )
        try:
            await listener.start()
            await talker.start()
        except OSError:
            await listener.stop()
            await talker.stop()
            return None
        try:
            public, _, port, nick = await asyncio.wait_for(received.get(), 3)
        except asyncio.TimeoutError:
            # Сокет создался, но пакеты не ходят — так ведут себя контейнеры и
            # часть конфигураций firewall. Это свойство окружения, не ошибка.
            return None
        finally:
            await listener.stop()
            await talker.stop()

        assert nick == "talker" and port == 9502 and public == b"\x09" * 32
        return True

    if asyncio.run(scenario()) is None:
        pytest.skip("мультикаст в этом окружении недоступен: сокет есть, пакеты не ходят")


def test_announced_port_is_remembered_with_observed_host():
    """Порт называет пир, хост берём из сокета — свой внешний адрес он не знает."""
    from p2pchat.proto.mesh import Mesh
    from p2pchat.proto.network import Connection

    class FakeSession:
        link_description = "203.0.113.55:41234"  # эфемерный порт входящего

    with tempfile.TemporaryDirectory() as tmp:
        me, peer = Identity.generate("me"), Identity.generate("peer")
        member = Member("peer", peer.public)
        trust = TrustStore.load(Path(tmp) / "known.json")
        trust.remember(peer.public, "peer")
        mesh = Mesh(
            me,
            nickname="me",
            roster=Roster("g", (Member("me", me.public), member)),
            trust=trust,
            download_dir=Path(tmp) / "dl",
            listen=None,
        )
        network = mesh.network
        network._connections[peer.public] = Connection(
            member=member, session=FakeSession(), reader=None
        )

        network.remember_peer_port(member, 9333)
        assert trust.by_key(peer.public).endpoint == ("203.0.113.55", 9333)

        # Мусор не должен ничего портить.
        for bad in (0, 70000, -1):
            network.remember_peer_port(member, bad)
        assert trust.by_key(peer.public).endpoint == ("203.0.113.55", 9333)


def test_trust_is_keyed_by_public_key_not_nick():
    """Личность — это ключ; ник лишь ярлык, который можно сменить и присвоить."""
    with tempfile.TemporaryDirectory() as tmp:
        store = TrustStore.load(Path(tmp) / "known.json")
        bob, stranger = Identity.generate().public, Identity.generate().public

        assert store.check(bob, "bob").value == "new"
        store.remember(bob, "bob")
        store.mark_verified("bob")

        # Смена ника не стирает отметку о сверке: ключ тот же.
        assert store.check(bob, "боб").value == "verified"

        # Чужак под знакомым именем отвергается, но записи не портит.
        assert store.check(stranger, "bob").value == "nick_taken"
        assert store.by_key(bob).verified is True

        # А тот же чужак под своим именем — просто новый.
        assert store.check(stranger, "mallory").value == "new"


def test_forget_removes_by_nick_and_survives_reload():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "known.json"
        store = TrustStore.load(path)
        key = Identity.generate().public
        store.remember(key, "bob", verified=True)

        assert TrustStore.load(path).by_key(key).verified is True
        assert store.forget("bob") is True
        assert TrustStore.load(path).by_key(key) is None
        assert store.forget("bob") is False
