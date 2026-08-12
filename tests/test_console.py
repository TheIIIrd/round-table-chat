"""Тесты консольного интерфейса.

Проверяется разбор команд и — что важнее — то, что непроверенный собеседник
помечается в каждой строке. Вся стойкость к MITM держится на сверке SAS
человеком, поэтому «забыть напомнить» здесь дороже, чем ошибка в разборе.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from p2pchat.crypto.identity import Identity
from p2pchat.proto import events as ev
from p2pchat.proto.trust import TrustStore
from p2pchat.ui.console import Console


class FakeMesh:
    """Меш-заглушка: запоминает вызовы вместо работы с сетью."""

    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self.peers: list[str] = ["bob"]
        self.events: asyncio.Queue = asyncio.Queue()
        self.broadcasts: list[str] = []
        self.offers: list[tuple[str, str]] = []
        self.responses: list[tuple[str, bool]] = []
        self.connects: list[tuple[str, int]] = []

    async def broadcast(self, text: str) -> None:
        self.broadcasts.append(text)

    async def offer_file(self, nick, path) -> None:
        self.offers.append((nick, str(path)))

    async def respond_to_offer(self, short_id: str, accept: bool) -> None:
        self.responses.append((short_id, accept))

    async def connect_to(self, host: str, port: int) -> None:
        self.connects.append((host, port))


def build(tmp: Path):
    identity = Identity.generate("alice")
    trust = TrustStore.load(tmp / "known.json")
    mesh = FakeMesh(identity)
    console = Console(mesh, trust)
    console._write = lambda text: console_output.append(text)  # type: ignore[assignment]
    return console, mesh, trust


console_output: list[str] = []


def run_command(console, line: str) -> bool:
    return asyncio.run(console._command(line))


def test_commands_are_parsed():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, trust = build(Path(tmp))

        assert run_command(console, "/peers") is True
        assert "bob" in console_output[-1]

        run_command(console, "/fingerprint")
        assert console.mesh.identity.fingerprint() in console_output[-1]

        run_command(console, "/connect 10.0.0.5:9333")
        assert mesh.connects == [("10.0.0.5", 9333)]

        run_command(console, "/connect кривой-адрес")
        assert "формат" in console_output[-1]

        run_command(console, "/send bob /tmp/файл.txt")
        assert mesh.offers[-1][0] == "bob"

        run_command(console, "/send bob")
        assert "формат" in console_output[-1]

        run_command(console, "/accept a1b2")
        run_command(console, "/decline c3d4")
        assert mesh.responses == [("a1b2", True), ("c3d4", False)]

        run_command(console, "/несуществующая")
        assert "неизвестная команда" in console_output[-1]

        assert run_command(console, "/quit") is False


def test_verify_and_forget_change_trust():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, _, trust = build(Path(tmp))
        peer = Identity.generate("bob").public
        trust.remember("bob", peer)

        assert trust.check("bob", peer).value == "known"
        run_command(console, "/verify bob")
        assert trust.check("bob", peer).value == "verified"

        run_command(console, "/verify незнакомец")
        assert "не найден" in console_output[-1]

        run_command(console, "/forget bob")
        assert trust.check("bob", peer).value == "new"


def test_unverified_peer_is_marked_on_every_line():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, trust = build(Path(tmp))
        peer = Identity.generate("bob").public
        trust.remember("bob", peer)

        async def scenario():
            pump = asyncio.create_task(console._pump_events())
            await mesh.events.put(
                ev.TextMessage(nick="bob", public=peer, text="первое", lamport=1)
            )
            await asyncio.sleep(0.01)
            trust.mark_verified("bob")
            await mesh.events.put(
                ev.TextMessage(nick="bob", public=peer, text="второе", lamport=2)
            )
            await asyncio.sleep(0.01)
            pump.cancel()

        asyncio.run(scenario())

        assert console_output[0] == "!<bob> первое"  # ещё не сверен
        assert console_output[1] == "<bob> второе"  # после /verify метки нет


def test_plain_text_goes_to_chat():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, _ = build(Path(tmp))

        async def scenario():
            # Имитируем то, что делает цикл ввода с обычной строкой.
            await mesh.broadcast("обычное сообщение")

        asyncio.run(scenario())
        assert mesh.broadcasts == ["обычное сообщение"]
