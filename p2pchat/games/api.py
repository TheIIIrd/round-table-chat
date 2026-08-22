"""Контракт, которому подчиняется любая игра.

Главное правило: **игра не знает о существовании сети.** Она получает событие
и возвращает список намерений — сказать всем, шепнуть одному, завершиться.
Превращает намерения в сообщения хозяин игры.

Отсюда три следствия, ради которых всё и затевалось:

* правила тестируются целиком без сокетов, бота и ключей;
* вся защита (таймауты, лимиты, изоляция) живёт в одном месте и не дублируется
  в каждой игре;
* игра физически не может ни прочитать файл, ни открыть соединение — ей просто
  нечем.

Случайность передаётся снаружи (``random.Random``), иначе тесты на правила
невозможны. В бою туда идёт генератор, засеянный из ``secrets``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from random import Random
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Say:
    """Сообщение всем участникам чата."""

    text: str


@dataclass(frozen=True)
class Whisper:
    """Сообщение лично одному игроку.

    В попарном меше это просто отправка в его сессию, поэтому приватная
    раздача карт или ролей достаётся бесплатно и остаётся сквозь шифрование.
    """

    player: str
    text: str


@dataclass(frozen=True)
class Finish:
    """Партия окончена; хозяин освободит место под следующую."""

    summary: str


Action = Say | Whisper | Finish


@runtime_checkable
class Game(Protocol):
    """Интерфейс игры. Реализация — обычный класс без ввода-вывода."""

    name: str  # короткое имя для команды: c4, durak
    title: str  # человеческое название
    min_players: int
    max_players: int
    verbs: frozenset[str]  # канонические (английские) команды игры
    aliases: dict[str, str]  # русские синонимы: слово -> каноническая команда

    def start(self, players: Sequence[str]) -> list[Action]:
        """Партия начинается. Порядок игроков уже перемешан хозяином."""

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        """Ход или запрос. ``verb`` гарантированно из ``verbs``."""

    def on_leave(self, player: str) -> list[Action]:
        """Игрок отключился. Игра решает: пауза, замена, конец партии."""

    def tick(self, now: float) -> list[Action]:
        """Вызывается примерно раз в секунду — для таймаутов хода."""

    def snapshot_for(self, player: str) -> str:
        """Что показать игроку, который вернулся после обрыва."""


def canonical(verb: str, verbs: frozenset[str], aliases: dict[str, str]) -> str | None:
    """Приводит команду к канонической форме.

    Английский вариант — основной и единственный, который показывают подсказки.
    Русский работает молча: человеку, который пишет «!ход», не нужно объяснять,
    что «на самом деле» команда называется drop.
    """
    lowered = verb.lower()
    if lowered in verbs:
        return lowered
    return aliases.get(lowered)


class GameError(Exception):
    """Некорректный ход. Хозяин превратит это в сообщение игроку."""


def shuffled(items: Sequence[str], rng: Random) -> list[str]:
    result = list(items)
    rng.shuffle(result)
    return result
