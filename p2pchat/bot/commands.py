"""Команды бота.

Кубики берут случайность из ``secrets``, а не из ``random``: последний —
детерминированный Mersenne Twister, по нескольким результатам его состояние
восстанавливается. Оговорка из обсуждения остаётся в силе: тот, кто держит
хост бота, видит результат до отправки, так что для ставок это не годится —
там нужна совместная генерация с коммитами.
"""

from __future__ import annotations

import secrets

from .registry import Context, Registry

MAX_DICE = 20
MAX_SIDES = 1000

registry = Registry()


@registry.command(
    "roll",
    pattern=r"(\d{1,2})?d(\d{1,4})\s*([+-]\s*\d{1,4})?",
    help="бросок кубиков, например !roll d20 или !roll 3d6+2",
)
def roll(ctx: Context, count: str | None, sides: str, modifier: str | None) -> str:
    number = int(count) if count else 1
    faces = int(sides)
    if not 1 <= number <= MAX_DICE:
        return f"{ctx.nick}: кубиков должно быть от 1 до {MAX_DICE}."
    if not 2 <= faces <= MAX_SIDES:
        return f"{ctx.nick}: граней должно быть от 2 до {MAX_SIDES}."

    rolls = [secrets.randbelow(faces) + 1 for _ in range(number)]
    shift = int(modifier.replace(" ", "")) if modifier else 0
    total = sum(rolls) + shift

    notation = f"{number}d{faces}" + (f"{shift:+d}" if shift else "")
    if number == 1 and not shift:
        return f"{ctx.nick} бросает {notation}: {total}"
    detail = " + ".join(str(value) for value in rolls)
    tail = f" {shift:+d}" if shift else ""
    return f"{ctx.nick} бросает {notation}: [{detail}]{tail} = {total}"


@registry.command("coin", help="подбросить монету")
def coin(ctx: Context) -> str:
    return f"{ctx.nick} подбрасывает монету: {'орёл' if secrets.randbelow(2) else 'решка'}"


@registry.command(
    "choose",
    pattern=r"(.{1,150})",
    help="выбрать из вариантов через запятую: !choose пицца, суши, паста",
)
def choose(ctx: Context, raw: str) -> str:
    options = [item.strip() for item in raw.split(",") if item.strip()]
    if len(options) < 2:
        return f"{ctx.nick}: нужно хотя бы два варианта через запятую."
    return f"{ctx.nick}: {options[secrets.randbelow(len(options))]}"


@registry.command("help", help="список команд")
def help_command(ctx: Context) -> str:
    return "Команды бота:\n" + "\n".join(registry.help_lines())
