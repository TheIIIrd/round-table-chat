"""Тесты командной строки.

Появились после настоящей поломки: флаг `--discover` был добавлен в обработчик,
но не в парсер, и `p2pchat chat` падал с ``AttributeError`` при запуске. Ни один
тест этого не ловил, потому что до CLI они просто не доходили.

Поэтому здесь два уровня. Первый — механическая сверка: у каждой подкоманды
разбираются аргументы, и каждое обращение вида ``args.что_то`` в её обработчике
должно существовать в разобранном пространстве имён. Такую ошибку больше не
пропустить, даже если забыть написать тест на новый флаг. Второй — прогон
команд, которые не требуют сети.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
from pathlib import Path

import pytest

from p2pchat import __main__ as cli
from p2pchat.crypto.identity import Identity
from p2pchat.proto.roster import Roster

SUBCOMMANDS = {
    "keygen": ["keygen"],
    "whoami": ["whoami"],
    "invite": ["invite"],
    "roster new": ["roster", "new", "друзья"],
    "roster add": ["roster", "add", "боб", "11" * 32],
    "roster add-invite": ["roster", "add-invite", "p2pchat:AAAA"],
    "roster show": ["roster", "show"],
    "chat": ["chat"],
    "bot": ["bot"],
}


def _attributes_read_by(handler) -> set[str]:
    """Собирает все ``args.X``, которые читает обработчик."""
    source = inspect.getsource(handler)
    tree = ast.parse(textwrap.dedent(source))
    argument = next(iter(inspect.signature(handler).parameters))
    found = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == argument
        ):
            found.add(node.attr)
    return found


@pytest.mark.parametrize("label", sorted(SUBCOMMANDS))
def test_every_argument_handler_reads_is_defined(label):
    """Обработчик не должен обращаться к аргументу, которого нет в парсере."""
    parser = cli.build_parser()
    args = parser.parse_args(SUBCOMMANDS[label])
    for attribute in _attributes_read_by(args.handler):
        assert hasattr(args, attribute), (
            f"{label}: обработчик читает args.{attribute}, "
            f"но парсер такого аргумента не объявляет"
        )


def test_chat_and_bot_accept_discover_flag():
    parser = cli.build_parser()
    assert parser.parse_args(["chat"]).discover == "off"
    assert parser.parse_args(["chat", "--discover", "lan"]).discover == "lan"
    assert parser.parse_args(["bot", "--discover", "lan"]).discover == "lan"
    with pytest.raises(SystemExit):
        parser.parse_args(["chat", "--discover", "телепатия"])


def test_address_parsing():
    assert cli._split_address("127.0.0.1:9333") == ("127.0.0.1", 9333)
    assert cli._parse_listen("none") is None
    for bad in ("9333", "host:", ":9333", "host:порт"):
        with pytest.raises(ValueError):
            cli._split_address(bad)


def test_keygen_invite_and_roster_roundtrip(tmp_path, monkeypatch):
    """Полный путь новичка: ключ → приглашение → ростер, без единого сокета."""
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    home = tmp_path / "alice"

    assert cli.main(["--home", str(home), "keygen", "--nick", "alice"]) == 0
    assert (home / "id.key").exists()
    assert cli.main(["--home", str(home), "whoami"]) == 0
    assert cli.main(["--home", str(home), "keygen"]) == 1  # второй раз не перезаписываем

    assert cli.main(["--home", str(home), "roster", "new", "друзья"]) == 0
    bob = Identity.generate("боб")
    assert (
        cli.main(
            ["--home", str(home), "roster", "add", "боб", bob.public.hex(), "--address", "10.0.0.2:9333"]
        )
        == 0
    )
    assert cli.main(["--home", str(home), "roster", "show"]) == 0

    roster = Roster.load(home / "roster.json")
    assert roster.by_nick("боб") is not None


def test_invite_add_invite_cycle(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    alice, bob = tmp_path / "a", tmp_path / "b"

    cli.main(["--home", str(alice), "keygen", "--nick", "alice"])
    cli.main(["--home", str(bob), "keygen", "--nick", "bob"])
    capsys.readouterr()

    cli.main(["--home", str(alice), "invite", "--address", "203.0.113.10:9333"])
    invite_line = next(
        line for line in capsys.readouterr().out.splitlines() if line.startswith("p2pchat:")
    )

    cli.main(["--home", str(bob), "roster", "new", "друзья"])
    assert cli.main(["--home", str(bob), "roster", "add-invite", invite_line]) == 0
    assert Roster.load(bob / "roster.json").by_nick("alice") is not None


def test_broken_invite_reports_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    home = tmp_path / "a"
    cli.main(["--home", str(home), "keygen", "--nick", "alice"])
    cli.main(["--home", str(home), "roster", "new", "друзья"])
    capsys.readouterr()

    assert cli.main(["--home", str(home), "roster", "add-invite", "p2pchat:МУСОР"]) == 1
    assert "Ошибка" in capsys.readouterr().err


def test_group_invite_cycle(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    alice, carol = tmp_path / "a", tmp_path / "c"

    cli.main(["--home", str(alice), "keygen", "--nick", "alice"])
    cli.main(["--home", str(carol), "keygen", "--nick", "carol"])
    cli.main(["--home", str(alice), "roster", "new", "друзья"])
    cli.main(
        ["--home", str(alice), "roster", "add", "боб", Identity.generate().public.hex()]
    )
    capsys.readouterr()

    cli.main(["--home", str(alice), "invite", "--group"])
    blob = next(
        line for line in capsys.readouterr().out.splitlines() if line.startswith("p2pchat-group:")
    )
    assert cli.main(["--home", str(carol), "roster", "add-invite", blob]) == 0

    original = Roster.load(alice / "roster.json")
    copied = Roster.load(carol / "roster.json")
    assert copied.group_id == original.group_id


def test_missing_key_is_reported(tmp_path, capsys):
    assert cli.main(["--home", str(tmp_path / "пусто"), "whoami"]) == 1
    assert "keygen" in capsys.readouterr().err


def test_keygen_from_env_requires_real_passphrase(tmp_path, monkeypatch):
    monkeypatch.delenv("P2PCHAT_PASSPHRASE", raising=False)
    assert cli.main(["--home", str(tmp_path / "x"), "keygen", "--key-from-env"]) == 1

    monkeypatch.setenv("P2PCHAT_PASSPHRASE", "коротко")
    assert cli.main(["--home", str(tmp_path / "y"), "keygen", "--key-from-env"]) == 1

    monkeypatch.setenv("P2PCHAT_PASSPHRASE", "достаточно-длинная")
    assert cli.main(["--home", str(tmp_path / "z"), "keygen", "--key-from-env"]) == 0


def test_chat_refuses_when_not_in_roster(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    home = tmp_path / "a"
    cli.main(["--home", str(home), "keygen", "--nick", "alice"])
    (home / "roster.json").write_text(
        json.dumps({"name": "чужая", "members": [{"nick": "боб", "key": "22" * 32}]}),
        encoding="utf-8",
    )
    capsys.readouterr()

    assert cli.main(["--home", str(home), "chat", "--listen", "none"]) == 1
    assert "ростере" in capsys.readouterr().err


def test_home_directory_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a, **k: "пассфраза-достаточная")
    first, second = tmp_path / "1", tmp_path / "2"
    cli.main(["--home", str(first), "keygen", "--nick", "alice"])
    cli.main(["--home", str(second), "keygen", "--nick", "alice"])

    assert Identity.load(first / "id.key", "пассфраза-достаточная").public != Identity.load(
        second / "id.key", "пассфраза-достаточная"
    ).public
