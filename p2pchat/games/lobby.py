"""Лобби и хозяин партии.

Здесь живёт всё, что одинаково для любой игры: набор игроков, запуск, таймауты,
уход и возвращение участников. Игра об этом не знает и не должна.

Три вещи, которые легко забыть и которые дороже всего стоят в живой партии:

* **Реконнект.** Пиры отваливаются и возвращаются. Вернувшемуся нужно заново
  прислать его приватное состояние — руку, роль, положение на доске. Без этого
  он остаётся слепым до конца партии.
* **Таймаут хода.** Один ушедший игрок иначе вешает партию навсегда.
* **Таймаут набора.** Лобби, открытое и забытое, блокирует следующую игру.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from random import Random

from .api import Action, Finish, Game, GameError, Say, Whisper, canonical, shuffled

GATHER_TIMEOUT = 180.0
LOBBY_VERBS = frozenset({"game", "join", "leave", "start", "stop", "who"})
LOBBY_ALIASES = {
    "игра": "game",
    "игры": "game",
    "войти": "join",
    "выйти": "leave",
    "начать": "start",
    "стоп": "stop",
    "прервать": "stop",
    "кто": "who",
}

GAME_ALIASES = {
    "дурак": "durak",
    "мафия": "mafia",
    "виселица": "hangman",
    "четыре": "c4",
    "четыревряд": "c4",
}

GameFactory = Callable[[Random], Game]


class Phase(Enum):
    IDLE = "idle"
    GATHERING = "gathering"
    RUNNING = "running"


@dataclass
class GameHost:
    """Одна активная партия (или её отсутствие) на весь чат."""

    catalog: dict[str, GameFactory]
    rng: Random
    gather_timeout: float = GATHER_TIMEOUT

    phase: Phase = Phase.IDLE
    game: Game | None = None
    pending: GameFactory | None = None
    pending_name: str = ""
    players: list[str] = field(default_factory=list)
    opener: str = ""
    opened_at: float = 0.0

    # --- маршрутизация --------------------------------------------------------

    def resolve(self, verb: str) -> str | None:
        """Каноническая форма команды или ``None``, если она не наша."""
        lobby = canonical(verb, LOBBY_VERBS, LOBBY_ALIASES)
        if lobby is not None:
            return lobby
        if self.game is None:
            return None
        return canonical(verb, self.game.verbs, getattr(self.game, "aliases", {}))

    def owns(self, verb: str) -> bool:
        return self.resolve(verb) is not None

    def dispatch(self, player: str, verb: str, rest: str, now: float | None = None) -> list[Action]:
        now = time.monotonic() if now is None else now
        verb = self.resolve(verb) or verb.lower()
        try:
            if verb in LOBBY_VERBS:
                return self._lobby(player, verb, rest.strip(), now)
            if self.game is None or self.phase is not Phase.RUNNING:
                return [Say(f"{player}: сейчас нет активной партии. !game — список игр.")]
            if player not in self.players:
                return [Whisper(player, "Вы не участвуете в этой партии.")]
            return self._collect(self.game.handle(player, verb, rest.strip()))
        except GameError as exc:
            return [Whisper(player, f"Так нельзя: {exc}")]

    # --- лобби ----------------------------------------------------------------

    def _lobby(self, player: str, verb: str, rest: str, now: float) -> list[Action]:
        if verb == "game":
            return self._open(player, rest, now)
        if verb == "join":
            return self._join(player)
        if verb == "leave":
            return self._leave(player, voluntary=True)
        if verb == "start":
            return self._start(player, now)
        if verb == "stop":
            return self._stop(player)
        return self._who(player)

    def _open(self, player: str, name: str, now: float) -> list[Action]:
        if not name:
            listing = ", ".join(
                f"{key} — {factory(Random(0)).title}"
                for key, factory in sorted(self.catalog.items())
            )
            return [Say(f"Доступные игры: {listing}\nНачать: !game <имя>, затем !join и !start")]

        if self.phase is not Phase.IDLE:
            return [Say(f"{player}: уже идёт «{self._current_title()}». Сначала !stop.")]

        factory = self.catalog.get(GAME_ALIASES.get(name.lower(), name.lower()))
        if factory is None:
            return [Say(f"{player}: игра «{name}» неизвестна. !game покажет список.")]

        probe = factory(Random(0))
        self.phase = Phase.GATHERING
        self.pending = factory
        self.pending_name = GAME_ALIASES.get(name.lower(), name.lower())
        self.players = [player]
        self.opener = player
        self.opened_at = now
        return [
            Say(
                f"{player} собирает игру «{probe.title}» "
                f"({probe.min_players}–{probe.max_players} игроков).\n"
                f"Присоединиться: !join. Начать: !start."
            )
        ]

    def _join(self, player: str) -> list[Action]:
        if self.phase is Phase.RUNNING:
            return [Whisper(player, "Партия уже идёт, дождитесь следующей.")]
        if self.phase is not Phase.GATHERING or self.pending is None:
            return [Whisper(player, "Сейчас никто не собирает игру. !game <имя> — начать сбор.")]
        if player in self.players:
            return [Whisper(player, "Вы уже в списке.")]

        probe = self.pending(Random(0))
        if len(self.players) >= probe.max_players:
            return [Whisper(player, f"Мест нет: максимум {probe.max_players}.")]

        self.players.append(player)
        return [Say(f"{player} в игре ({len(self.players)}/{probe.max_players}). {self._need()}")]

    def _leave(self, player: str, *, voluntary: bool) -> list[Action]:
        if self.phase is Phase.GATHERING and player in self.players:
            self.players.remove(player)
            if not self.players:
                self._reset()
                return [Say("Сбор отменён: не осталось желающих.")]
            if player == self.opener:
                self.opener = self.players[0]
            return [Say(f"{player} вышел из списка. {self._need()}")]

        if self.phase is Phase.RUNNING and self.game is not None and player in self.players:
            actions = self._collect(self.game.on_leave(player))
            return [Say(f"{player} покинул партию."), *actions]

        if voluntary:
            return [Whisper(player, "Вы никуда не записаны.")]
        return []

    def _start(self, player: str, now: float) -> list[Action]:
        if self.phase is not Phase.GATHERING or self.pending is None:
            return [Whisper(player, "Нечего запускать: сбор не идёт.")]

        probe = self.pending(Random(0))
        if len(self.players) < probe.min_players:
            return [Whisper(player, f"Нужно хотя бы {probe.min_players} игроков. {self._need()}")]

        self.game = self.pending(self.rng)
        self.phase = Phase.RUNNING
        self.players = shuffled(self.players, self.rng)
        return [
            Say(f"Партия «{self.game.title}» началась: {', '.join(self.players)}."),
            *self._collect(self.game.start(tuple(self.players))),
        ]

    def _stop(self, player: str) -> list[Action]:
        if self.phase is Phase.IDLE:
            return [Whisper(player, "Нечего останавливать.")]
        if player not in self.players:
            return [Whisper(player, "Останавливать может только участник.")]
        title = self._current_title()
        self._reset()
        return [Say(f"{player} прервал «{title}».")]

    def _who(self, player: str) -> list[Action]:
        if self.phase is Phase.IDLE:
            return [Whisper(player, "Сейчас никто не играет. !game — список игр.")]
        return [Say(f"«{self._current_title()}»: {', '.join(self.players)}")]

    # --- события извне --------------------------------------------------------

    def on_peer_lost(self, player: str) -> list[Action]:
        return self._leave(player, voluntary=False)

    def on_peer_back(self, player: str) -> list[Action]:
        """Вернувшемуся возвращаем его приватное состояние."""
        if self.phase is not Phase.RUNNING or self.game is None or player not in self.players:
            return []
        snapshot = self.game.snapshot_for(player)
        if not snapshot:
            return []
        return [Whisper(player, f"Вы вернулись в «{self.game.title}».\n{snapshot}")]

    def tick(self, now: float | None = None) -> list[Action]:
        now = time.monotonic() if now is None else now
        if self.phase is Phase.GATHERING and now - self.opened_at > self.gather_timeout:
            title = self._current_title()
            self._reset()
            return [Say(f"Сбор на «{title}» отменён: никто не начал вовремя.")]
        if self.phase is Phase.RUNNING and self.game is not None:
            return self._collect(self.game.tick(now))
        return []

    # --- служебное ------------------------------------------------------------

    def _collect(self, actions: list[Action]) -> list[Action]:
        """Ловит ``Finish`` и освобождает место под следующую партию."""
        if any(isinstance(action, Finish) for action in actions):
            self._reset()
        return actions

    def _need(self) -> str:
        if self.pending is None:
            return ""
        probe = self.pending(Random(0))
        missing = probe.min_players - len(self.players)
        return f"Нужно ещё {missing}." if missing > 0 else "Можно начинать: !start."

    def _current_title(self) -> str:
        if self.game is not None:
            return self.game.title
        if self.pending is not None:
            return self.pending(Random(0)).title
        return "—"

    def _reset(self) -> None:
        self.phase = Phase.IDLE
        self.game = None
        self.pending = None
        self.pending_name = ""
        self.players = []
        self.opener = ""
        self.opened_at = 0.0
