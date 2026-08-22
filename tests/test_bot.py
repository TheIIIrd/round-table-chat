"""Тесты бота: разбор команд, ограничения, поведение в меше."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access,import-outside-toplevel

from __future__ import annotations

import asyncio

from p2pchat.bot import commands as bot_commands
from p2pchat.bot.registry import Context, Registry, TokenBucket
from p2pchat.bot.runner import Bot
from p2pchat.crypto.identity import Identity
from p2pchat.proto import events as ev
from p2pchat.proto.roster import Member, Roster
from p2pchat.proto.trust import TrustStore
from tests.conftest import free_ports, run_async, wait_connected, wait_for

CTX = Context(nick="alice", public=b"\x01" * 32)


def fresh_ctx(nick: str = "alice") -> Context:
    """Новый отправитель на каждый вызов.

    Ограничитель частоты считает токены по ключу отправителя, поэтому серия
    вызовов от одного и того же «человека» упрётся в лимит — и правильно
    сделает. Тестам, которые проверяют не лимит, нужен каждый раз новый пир.
    """
    import secrets

    return Context(nick=nick, public=secrets.token_bytes(32))


def dispatch(text: str, ctx: Context | None = None) -> str | None:
    return asyncio.run(bot_commands.registry.dispatch(ctx or fresh_ctx(), text))


def test_dice_roll_stays_in_range():
    for _ in range(200):
        reply = dispatch("!roll d20")
        assert reply is not None
        value = int(reply.rsplit(":", 1)[1])
        assert 1 <= value <= 20


def test_dice_roll_with_count_and_modifier():
    reply = dispatch("!roll 3d6+2")
    assert reply is not None and "3d6+2" in reply
    total = int(reply.rsplit("=", 1)[1])
    assert 5 <= total <= 20  # 3..18 плюс 2


def test_dice_limits_enforced():
    assert "от 1 до" in dispatch("!roll 99d6")
    assert "граней" in dispatch("!roll d1")


def test_malformed_arguments_do_not_crash():
    assert dispatch("!roll не кубик") is not None
    assert dispatch("!roll d") is not None
    assert dispatch("!roll " + "9" * 100) is not None


def test_only_prefixed_commands_react():
    assert dispatch("roll d20") is None
    assert dispatch("поговорим про !roll d20?") is None
    assert dispatch("!неизвестная") is None
    assert dispatch("!roll d20" + "x" * 300) is None  # длина отсекается до разбора


def test_choose_needs_two_options():
    assert "два варианта" in dispatch("!choose только одно")
    assert dispatch("!choose пицца, суши") in ("alice: пицца", "alice: суши")


def test_rate_limit_stops_flood():
    ctx = Context(nick="flooder", public=b"\x02" * 32)
    replies = [dispatch("!coin", ctx) for _ in range(20)]
    answered = [r for r in replies if r is not None]
    assert 0 < len(answered) <= 6  # первые проходят, остальные молча отбрасываются


def test_token_bucket_refills():
    bucket = TokenBucket(capacity=2, refill=1000.0, tokens=0)
    import time

    time.sleep(0.01)
    assert bucket.take() is True


def test_handler_timeout_is_reported():
    registry = Registry()

    @registry.command("hang", summary="зависает")
    async def hang(ctx):
        await asyncio.sleep(10)
        return "не должно дойти"

    import p2pchat.bot.registry as reg

    original = reg.HANDLER_TIMEOUT
    reg.HANDLER_TIMEOUT = 0.05
    try:
        reply = asyncio.run(registry.dispatch(CTX, "!hang"))
        assert "слишком долго" in reply
    finally:
        reg.HANDLER_TIMEOUT = original


def test_failing_handler_does_not_propagate():
    registry = Registry()

    @registry.command("boom", summary="падает")
    def boom(ctx):
        raise RuntimeError("внутренняя ошибка")

    reply = asyncio.run(registry.dispatch(CTX, "!boom"))
    assert "не выполнилась" in reply


def test_bot_answers_in_group():
    async def scenario(tmp_path):
        ports = free_ports(2)
        human = Identity.generate("alice")
        robot = Identity.generate("dice")
        roster = Roster(
            name="game",
            members=(
                Member("alice", human.public, "127.0.0.1", ports[0]),
                Member("dice", robot.public, "127.0.0.1", ports[1], is_bot=True),
            ),
        )
        from p2pchat.proto.mesh import Mesh

        mesh = Mesh(
            human,
            nickname="alice",
            roster=roster,
            trust=TrustStore.load(tmp_path / "known.json"),
            download_dir=tmp_path / "dl",
            listen=("127.0.0.1", ports[0]),
        )
        bot = Bot(
            robot,
            nickname="dice",
            roster=roster,
            trust_path=tmp_path / "bot-known.json",
            listen=("127.0.0.1", ports[1]),
        )
        bot_task = asyncio.create_task(bot.run())
        await mesh.start()
        try:
            await wait_connected(mesh, 1)
            await mesh.broadcast("!roll d20")
            answer = await wait_for(mesh, ev.TextMessage)
            assert answer.nick == "dice" and answer.is_bot
            value = int(answer.text.rsplit(":", 1)[1])
            assert 1 <= value <= 20
            assert answer.render().startswith("┃ ")  # реплики бота выделяются полосой
        finally:
            bot_task.cancel()
            await mesh.stop()

    run_async(scenario)


def test_bot_declines_files():
    async def scenario(tmp_path):
        ports = free_ports(2)
        human = Identity.generate("alice")
        robot = Identity.generate("dice")
        roster = Roster(
            name="game",
            members=(
                Member("alice", human.public, "127.0.0.1", ports[0]),
                Member("dice", robot.public, "127.0.0.1", ports[1], is_bot=True),
            ),
        )
        from p2pchat.proto.mesh import Mesh

        mesh = Mesh(
            human,
            nickname="alice",
            roster=roster,
            trust=TrustStore.load(tmp_path / "known.json"),
            download_dir=tmp_path / "dl",
            listen=("127.0.0.1", ports[0]),
        )
        bot = Bot(
            robot,
            nickname="dice",
            roster=roster,
            trust_path=tmp_path / "bot-known.json",
            listen=("127.0.0.1", ports[1]),
        )
        bot_task = asyncio.create_task(bot.run())
        await mesh.start()
        try:
            await wait_connected(mesh, 1)
            source = tmp_path / "payload.bin"
            source.write_bytes(b"Z" * 2000)
            await mesh.offer_file("dice", source)
            failure = await wait_for(mesh, ev.FileFailed)
            assert "отказ" in failure.reason
        finally:
            bot_task.cancel()
            await mesh.stop()

    run_async(scenario)


def test_bot_ignores_other_bots():
    """Иначе два бота уйдут в бесконечную переписку."""

    async def scenario(tmp_path):
        ports = free_ports(1)
        robot = Identity.generate("dice")
        roster = Roster(
            name="g", members=(Member("dice", robot.public, "127.0.0.1", ports[0], is_bot=True),)
        )
        bot = Bot(
            robot,
            nickname="dice",
            roster=roster,
            trust_path=tmp_path / "bot-known.json",
            listen=None,
        )
        sent = []
        bot.mesh.broadcast = lambda text: sent.append(text)  # type: ignore[assignment]

        await bot._handle(
            ev.TextMessage(
                nick="other", public=b"\x03" * 32, text="!roll d20", is_bot=True
            )
        )
        assert sent == []

    run_async(scenario)
