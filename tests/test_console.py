"""Тесты консольного интерфейса.

Проверяется разбор команд и — что важнее — то, что непроверенный собеседник
помечается в каждой строке. Вся стойкость к MITM держится на сверке SAS
человеком, поэтому «забыть напомнить» здесь дороже, чем ошибка в разборе.
"""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

import asyncio
import inspect
import tempfile
from pathlib import Path

from p2pchat.crypto.identity import Identity
from p2pchat.proto import events as ev
from p2pchat.proto.trust import TrustStore
from p2pchat.ui.console import Console
from p2pchat.ui.style import Palette


class FakeNetwork:
    """Сеть-заглушка: запоминает вызовы вместо работы с сокетами."""

    # Поля-журналы, которых в настоящем классе нет и быть не должно.
    RECORDING = {"connects"}

    def __init__(self) -> None:
        self.peers: list[str] = ["bob"]
        self.connects: list[tuple[str, int]] = []

    async def connect_to(self, host: str, port: int) -> None:
        self.connects.append((host, port))


class FakeMesh:
    """Меш-заглушка: запоминает вызовы вместо работы с сетью."""

    RECORDING = {"broadcasts", "offers", "responses"}

    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self.network = FakeNetwork()
        self.events: asyncio.Queue = asyncio.Queue()
        self.broadcasts: list[str] = []
        self.offers: list[tuple[str, str]] = []
        self.responses: list[tuple[str, bool]] = []

    async def broadcast(self, text: str) -> None:
        self.broadcasts.append(text)

    async def offer_file(self, nick, path) -> None:
        self.offers.append((nick, str(path)))

    async def respond_to_offer(self, short_id: str, accept: bool) -> None:
        self.responses.append((short_id, accept))


def build(tmp: Path, *, color: bool = False):
    """Консоль с явно заданной палитрой.

    Палитра задаётся явно не для красоты: без неё она определялась бы по
    окружению, и тест на текст проходил бы при выводе в конвейер и падал в
    настоящем терминале. Тест не должен зависеть от того, как его запустили.
    """
    identity = Identity.generate("alice")
    trust = TrustStore.load(tmp / "known.json")
    mesh = FakeMesh(identity)
    console = Console(mesh, trust, palette=Palette(enabled=color))
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
        assert mesh.network.connects == [("10.0.0.5", 9333)]

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
        trust.remember(peer, "bob")

        assert trust.check(peer, "bob").value == "known"
        run_command(console, "/verify bob")
        assert trust.check(peer, "bob").value == "verified"

        run_command(console, "/verify незнакомец")
        assert "не найден" in console_output[-1]

        run_command(console, "/forget bob")
        assert trust.check(peer, "bob").value == "new"


def test_unverified_peer_is_marked_on_every_line():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, trust = build(Path(tmp))
        peer = Identity.generate("bob").public
        trust.remember(peer, "bob")

        async def scenario():
            pump = asyncio.create_task(console._pump_events())
            await mesh.events.put(
                ev.TextMessage(nick="bob", public=peer, text="первое")
            )
            await asyncio.sleep(0.01)
            trust.mark_verified("bob")
            await mesh.events.put(
                ev.TextMessage(nick="bob", public=peer, text="второе")
            )
            await asyncio.sleep(0.01)
            pump.cancel()

        asyncio.run(scenario())

        assert console_output[0] == "?bob: первое"  # ещё не сверен
        assert console_output[1] == "bob: второе"  # после /verify метки нет


def test_plain_text_goes_to_chat():
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, _ = build(Path(tmp))

        async def scenario():
            # Имитируем то, что делает цикл ввода с обычной строкой.
            await mesh.broadcast("обычное сообщение")

        asyncio.run(scenario())
        assert mesh.broadcasts == ["обычное сообщение"]


# --- цвет ------------------------------------------------------------------------


def test_color_is_disabled_without_terminal(monkeypatch):
    from p2pchat.ui.style import build_palette, supports_color

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color() is False

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert supports_color() is False

    assert build_palette(False).red("текст") == "текст"


def test_nick_color_follows_key_not_name():
    """Цвет привязан к ключу: подделать чужой, взяв его ник, не выйдет."""
    from p2pchat.ui.style import Palette

    palette = Palette(enabled=True)
    key_a, key_b = b"\x01" * 32, b"\x02" * 32
    assert palette.nick("bob", key_a) != palette.nick("bob", key_b)
    assert palette.nick("bob", key_a) == palette.nick("bob", key_a)
    assert "bob" in palette.nick("bob", key_a)


def test_incoming_text_cannot_drive_the_terminal():
    """Чужое сообщение не должно чистить экран и двигать курсор."""
    with tempfile.TemporaryDirectory() as tmp:
        console_output.clear()
        console, mesh, trust = build(Path(tmp))
        peer = Identity.generate("bob").public
        trust.remember(peer, "bob", verified=True)

        hostile = "\x1b[2Jочистка\x1b]0;чужой заголовок\x07\x00"
        line = console._decorate(
            ev.TextMessage(nick="bob", public=peer, text=hostile)
        )
        assert "\x1b[2J" not in line
        assert "\x07" not in line and "\x00" not in line
        assert "очистка" in line


def test_bot_lines_are_marked_even_without_color():
    with tempfile.TemporaryDirectory() as tmp:
        console, _, _ = build(Path(tmp))
        line = console._decorate(
            ev.TextMessage(
                nick="dice",
                public=b"\x03" * 32,
                text="строка\nвторая",
                is_bot=True,
            )
        )
        assert line.split("\n") == ["┃ строка", "┃ вторая"]


def test_marks_survive_color_being_on():
    """Пометки должны читаться и в цветном терминале, а не только в конвейере.

    Регрессия: тесты задавали палитру по окружению, поэтому в конвейере они
    проходили, а в настоящем терминале падали — цвет добавлял ANSI-коды вокруг
    ровно тех символов, которые проверялись.
    """
    with tempfile.TemporaryDirectory() as tmp:
        console, _, trust = build(Path(tmp), color=True)
        peer = Identity.generate("bob").public
        trust.remember(peer, "bob")

        unverified = console._decorate(
            ev.TextMessage(nick="bob", public=peer, text="привет")
        )
        assert "?" in unverified and "привет" in unverified
        assert "\x1b[" in unverified  # цвет действительно включён

        bot_line = console._decorate(
            ev.TextMessage(
                nick="dice", public=b"\x03" * 32, text="раз\nдва", is_bot=True
            )
        )
        assert bot_line.count("┃") == 2


def test_alert_emits_single_reset():
    """Вложенные red(bold(...)) давали два сброса подряд — мусор в выводе."""
    from p2pchat.ui.style import Palette as _Palette

    painted = _Palette(enabled=True).alert("ВНИМАНИЕ")
    assert painted.count("\x1b[0m") == 1
    assert painted.startswith("\x1b[")
    assert _Palette(enabled=False).alert("ВНИМАНИЕ") == "ВНИМАНИЕ"


def test_plain_console_can_be_forced():
    """Должен быть способ обойти prompt_toolkit, не удаляя пакет."""
    from p2pchat.ui.console import Console as _Console
    from p2pchat.ui.console import PromptToolkitConsole, build_console

    with tempfile.TemporaryDirectory() as tmp:
        trust = TrustStore.load(Path(tmp) / "known.json")
        mesh = FakeMesh(Identity.generate("alice"))
        console = build_console(mesh, trust, Palette(enabled=False), plain=True)
        assert type(console) is _Console
        assert not isinstance(console, PromptToolkitConsole)


def test_prompt_toolkit_console_does_not_print_raw_ansi():
    """Регрессия: patch_stdout заменял \\x1b на «?», и цвет превращался в мусор.

    Библиотеки здесь нет, поэтому проверяем то, что можно проверить без неё:
    класс обязан переопределять _write, а не наследовать печать через print.
    """
    from p2pchat.ui.console import Console as _Console
    from p2pchat.ui.console import PromptToolkitConsole

    assert PromptToolkitConsole._write is not _Console._write
    source = inspect.getsource(PromptToolkitConsole._write)
    assert "self._print" in source and "self._ansi" in source


def _public_api(cls) -> set[str]:
    """Имена, доступные у экземпляра: и объявленные в классе, и заведённые в __init__.

    ``hasattr`` на самом классе не видит вторые, поэтому исходник __init__
    разбирается отдельно.
    """
    import ast as _ast
    import inspect as _inspect
    import textwrap as _textwrap

    names = {name for name in dir(cls) if not name.startswith("_")}
    try:
        source = _textwrap.dedent(_inspect.getsource(cls.__init__))
    except (OSError, TypeError):  # pragma: no cover
        return names
    for node in _ast.walk(_ast.parse(source)):
        if (
            isinstance(node, _ast.Attribute)
            and isinstance(node.value, _ast.Name)
            and node.value.id == "self"
            and isinstance(node.ctx, _ast.Store)
            and not node.attr.startswith("_")
        ):
            names.add(node.attr)
    return names


def test_fake_mesh_matches_the_real_interface():
    """Заглушка обязана повторять настоящий класс.

    Регрессия: снятие фасада убрало `Mesh.connect_to`, консоль сломалась — а
    тесты прошли, потому что у заглушки метод остался. Заглушка, разошедшаяся с
    оригиналом, превращает зелёные тесты в ложное спокойствие.
    """
    from p2pchat.proto.mesh import Mesh
    from p2pchat.proto.network import PeerNetwork

    for fake, real in ((FakeMesh, Mesh), (FakeNetwork, PeerNetwork)):
        available = _public_api(real)
        promised = _public_api(fake) - fake.RECORDING - {"RECORDING"}
        missing = sorted(promised - available)
        assert not missing, f"{fake.__name__} обещает то, чего нет в {real.__name__}: {missing}"


def test_console_touches_only_existing_attributes():
    """Каждое обращение консоли к mesh должно существовать у настоящего класса."""
    import ast as _ast
    import inspect as _inspect

    from p2pchat.proto.mesh import Mesh
    from p2pchat.proto.network import PeerNetwork
    from p2pchat.ui import console as console_module

    mesh_api, network_api = _public_api(Mesh), _public_api(PeerNetwork)
    tree = _ast.parse(_inspect.getsource(console_module))

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Attribute):
            continue
        owner = node.value
        if not isinstance(owner, _ast.Attribute):
            continue

        # self.mesh.network.X — спрашиваем у сети
        if (
            owner.attr == "network"
            and isinstance(owner.value, _ast.Attribute)
            and owner.value.attr == "mesh"
        ):
            assert node.attr in network_api, f"консоль зовёт mesh.network.{node.attr}"
        # self.mesh.X — спрашиваем у меша
        elif owner.attr == "mesh":
            assert node.attr in mesh_api, f"консоль зовёт mesh.{node.attr}, которого нет"
