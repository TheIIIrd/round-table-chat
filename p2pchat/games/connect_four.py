"""Connect Four — четыре в ряд.

Первая игра на каркасе выбрана намеренно простой: полная информация, никаких
секретов, правила умещаются в голове. Зато она прогоняет весь каркас целиком —
очередь ходов, таймаут, уход игрока, возвращение после обрыва.

Доска рисуется кружками; если у кого-то в терминале они разъезжаются, достаточно
поменять ``TOKENS`` на ``"XO"`` — на логику это не влияет.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from random import Random

from ..format import panel
from .api import Action, Finish, GameError, Say, Whisper

COLUMNS = 7
ROWS = 6
NEEDED = 4
TURN_TIMEOUT = 120.0
WARN_BEFORE = 30.0

TOKENS = ("●", "○")
EMPTY = "·"

DIRECTIONS = ((0, 1), (1, 0), (1, 1), (1, -1))


class ConnectFour:
    name = "c4"
    title = "Четыре в ряд"
    min_players = 2
    max_players = 2
    verbs = frozenset({"drop", "board"})
    aliases = {"ход": "drop", "ходи": "drop", "доска": "board"}

    def __init__(self, rng: Random) -> None:
        self._rng = rng
        self.board: list[list[int | None]] = [[None] * COLUMNS for _ in range(ROWS)]
        self.players: list[str] = []
        self.turn = 0
        self.deadline = 0.0
        self.warned = False
        self.finished = False
        self.moves = 0

    # --- события каркаса ------------------------------------------------------

    def start(self, players: Sequence[str]) -> list[Action]:
        self.players = list(players)
        self._arm(time.monotonic())
        return [
            Say(
                f"{self.players[0]} {TOKENS[0]} против {self.players[1]} {TOKENS[1]}\n"
                f"Ход: !drop <столбец 1–{COLUMNS}>, доска: !board\n"
                + self.render(footer=f"ходит {self._current()}")
            )
        ]

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        if verb == "board":
            return [Whisper(player, self.render(footer=f"ходит {self._current()}"))]

        if self.finished:
            raise GameError("партия уже окончена")
        if player != self._current():
            raise GameError(f"сейчас ходит {self._current()}")

        column = self._parse_column(rest)
        row = self._drop(column, self.turn)
        self.moves += 1

        if self._wins(row, column, self.turn):
            self.finished = True
            return [
                Say(self.render(footer=f"{player} — победа")),
                Finish(f"{player} собрал четыре в ряд. Поздравляем!"),
            ]

        if self.moves == ROWS * COLUMNS:
            self.finished = True
            return [
                Say(self.render(footer="ничья")),
                Finish("Доска заполнена — ничья."),
            ]

        self.turn = 1 - self.turn
        self._arm(time.monotonic())
        return [
            Say(
                f"{player} → столбец {column + 1}\n"
                + self.render(footer=f"ходит {self._current()}")
            )
        ]

    def on_leave(self, player: str) -> list[Action]:
        if self.finished or player not in self.players:
            return []
        self.finished = True
        winner = self.players[1 - self.players.index(player)]
        return [Finish(f"{player} покинул партию — победа достаётся {winner}.")]

    def tick(self, now: float) -> list[Action]:
        if self.finished or not self.players:
            return []
        remaining = self.deadline - now
        if remaining <= 0:
            self.finished = True
            loser = self._current()
            winner = self.players[1 - self.turn]
            return [Finish(f"{loser} не сходил вовремя — победа {winner}.")]
        if remaining <= WARN_BEFORE and not self.warned:
            self.warned = True
            return [Say(f"{self._current()}, осталось {int(remaining)} с на ход.")]
        return []

    def snapshot_for(self, player: str) -> str:
        if not self.players:
            return ""
        token = TOKENS[self.players.index(player)] if player in self.players else "—"
        return f"Вы играете {token}.\n" + self.render(footer=f"ходит {self._current()}")

    # --- правила --------------------------------------------------------------

    def render(self, footer: str = "") -> str:
        """Доска в рамке.

        Рамка, а не цвет: она отделяет доску от потока реплик в любом
        терминале и переживает копирование в другой чат.
        """
        header = " ".join(str(index + 1) for index in range(COLUMNS))
        rows = [
            " ".join(EMPTY if cell is None else TOKENS[cell] for cell in row) for row in self.board
        ]
        return panel("\n".join([*rows, header]), title=self.title, footer=footer)

    def _parse_column(self, rest: str) -> int:
        text = rest.strip()
        if not text.isdigit():
            raise GameError(f"нужен номер столбца от 1 до {COLUMNS}")
        column = int(text) - 1
        if not 0 <= column < COLUMNS:
            raise GameError(f"столбец должен быть от 1 до {COLUMNS}")
        if self.board[0][column] is not None:
            raise GameError(f"столбец {column + 1} заполнен")
        return column

    def _drop(self, column: int, side: int) -> int:
        for row in range(ROWS - 1, -1, -1):
            if self.board[row][column] is None:
                self.board[row][column] = side
                return row
        raise GameError(f"столбец {column + 1} заполнен")

    def _wins(self, row: int, column: int, side: int) -> bool:
        for delta_row, delta_column in DIRECTIONS:
            count = 1
            for sign in (1, -1):
                step = 1
                while True:
                    r = row + delta_row * step * sign
                    c = column + delta_column * step * sign
                    if not (0 <= r < ROWS and 0 <= c < COLUMNS) or self.board[r][c] != side:
                        break
                    count += 1
                    step += 1
            if count >= NEEDED:
                return True
        return False

    def _current(self) -> str:
        return self.players[self.turn]

    def _arm(self, now: float) -> None:
        self.deadline = now + TURN_TIMEOUT
        self.warned = False
