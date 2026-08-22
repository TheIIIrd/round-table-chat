"""Виселица.

Тот самый случай, где бот подходит идеально: секрет принадлежит ему по замыслу
игры, а не из-за компромисса. Никакого доверия к владельцу узла не требуется —
он и должен знать слово.

Игра кооперативная и без очерёдности: буквы называет кто угодно и когда угодно.
В чате это ощущается живее, чем строгая очередь, и заодно проверяет, что каркас
не навязывает пошаговую модель.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from random import Random

from ..format import panel
from .api import Action, Finish, GameError, Say, Whisper

MISTAKES_ALLOWED = 7
IDLE_TIMEOUT = 300.0
WARN_BEFORE = 60.0

WORDS = (
    "автомобиль баклажан вертолёт гитара дельфин ежевика жаворонок задача изумруд "
    "календарь лабиринт молоток настурция обезьяна пирамида равновесие сокровище тюльпан "
    "уравнение фонарь хризантема цистерна черепаха шахматы щавель эволюция юбилей ярмарка "
    "барабан велосипед голограмма доктрина единорог жемчужина зодиак институт клавиатура "
    "лестница маяк наковальня остров пельмени рюкзак самовар телескоп ультиматум фестиваль "
    "хоровод цыплёнок чемодан шиповник экватор эскалатор яблоко бабочка вулкан гербарий"
).split()
WORDS = tuple(WORDS)

GALLOWS = ("", "О", "О|", "О|-", "О|-<", "О|-<\\", "О|-<\\ ✗", "О|-<\\ ✗✗")


class Hangman:
    name = "hangman"
    title = "Виселица"
    min_players = 1
    max_players = 8
    verbs = frozenset({"letter", "word", "gallows"})
    aliases = {"буква": "letter", "слово": "word", "виселица": "gallows", "виселицa": "gallows"}

    def __init__(self, rng: Random) -> None:
        self._rng = rng
        self.secret = ""
        self.opened: set[str] = set()
        self.wrong: list[str] = []
        self.players: list[str] = []
        self.finished = False
        self.deadline = 0.0
        self.warned = False

    # --- каркас ---------------------------------------------------------------

    def start(self, players: Sequence[str]) -> list[Action]:
        self.players = list(players)
        self.secret = self._rng.choice(WORDS).lower()
        self._arm(time.monotonic())
        return [
            Say(
                "Загадано слово из "
                f"{len(self.secret)} букв. Буквы называет кто угодно, очереди нет.\n"
                "!letter <а> — назвать букву, !word <ответ> — слово целиком\n"
                + self.render()
            )
        ]

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        if verb == "gallows":
            return [Whisper(player, self.render())]
        if self.finished:
            raise GameError("партия уже окончена")
        self._arm(time.monotonic())
        return self._word(player, rest) if verb == "word" else self._letter(player, rest)

    def on_leave(self, player: str) -> list[Action]:
        if player in self.players:
            self.players.remove(player)
        if self.players or self.finished:
            return []
        self.finished = True
        return [Finish(f"Все разошлись. Слово было «{self.secret}».")]

    def tick(self, now: float) -> list[Action]:
        if self.finished:
            return []
        remaining = self.deadline - now
        if remaining <= 0:
            self.finished = True
            return [Finish(f"Никто не отвечает. Слово было «{self.secret}».")]
        if remaining <= WARN_BEFORE and not self.warned:
            self.warned = True
            return [Say(f"Осталась минута — слово всё ещё «{self.masked()}».")]
        return []

    def snapshot_for(self, player: str) -> str:
        return self.render() if self.secret else ""

    # --- правила --------------------------------------------------------------

    def masked(self) -> str:
        return " ".join(letter if letter in self.opened else "_" for letter in self.secret)

    def render(self) -> str:
        wrong = ", ".join(self.wrong) if self.wrong else "—"
        gallows = GALLOWS[min(len(self.wrong), len(GALLOWS) - 1)]
        left = MISTAKES_ALLOWED - len(self.wrong)
        return panel(
            f"{self.masked()}\nмимо: {wrong}   {gallows}",
            title=self.title,
            footer=f"попыток осталось {left}",
        )

    def _letter(self, player: str, rest: str) -> list[Action]:
        letter = rest.strip().lower().replace("ё", "е")
        if len(letter) != 1 or not letter.isalpha():
            raise GameError("назовите ровно одну букву")
        if letter in self.opened or letter in self.wrong:
            raise GameError(f"букву «{letter}» уже называли")

        target = self.secret.replace("ё", "е")
        if letter in target:
            for index, original in enumerate(target):
                if original == letter:
                    self.opened.add(self.secret[index])
            if all(ch in self.opened for ch in self.secret):
                self.finished = True
                return [Finish(f"{player} открыл последнюю букву. Слово: «{self.secret}».")]
            return [Say(f"{player}: «{letter}» есть.\n{self.render()}")]

        self.wrong.append(letter)
        if len(self.wrong) >= MISTAKES_ALLOWED:
            self.finished = True
            return [
                Say(f"{player}: «{letter}» мимо.\n{self.render()}"),
                Finish(f"Попытки кончились. Слово было «{self.secret}»."),
            ]
        return [Say(f"{player}: «{letter}» мимо.\n{self.render()}")]

    def _word(self, player: str, rest: str) -> list[Action]:
        guess = rest.strip().lower().replace("ё", "е")
        if not guess:
            raise GameError("назовите слово целиком")
        if guess == self.secret.replace("ё", "е"):
            self.finished = True
            self.opened.update(self.secret)
            return [Finish(f"{player} угадал слово: «{self.secret}».")]

        self.wrong.append(guess)
        if len(self.wrong) >= MISTAKES_ALLOWED:
            self.finished = True
            return [Finish(f"«{guess}» мимо, попытки кончились. Слово было «{self.secret}».")]
        return [Say(f"{player}: «{guess}» — не то.\n{self.render()}")]

    def _arm(self, now: float) -> None:
        self.deadline = now + IDLE_TIMEOUT
        self.warned = False
