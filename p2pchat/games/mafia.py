"""Мафия.

Игра, ради которой чат и существует: вся суть в разговоре, а бот-ведущий здесь
объективно лучше человека — раздаёт роли, не путается в ночных ходах и не
оговаривается.

Ночные ходы отправляются боту лично: в консоли это `/w <ник бота> !убить вася`.
Если написать то же самое в общий чат, ход увидят все — игра предупреждает об
этом при раздаче ролей, но защититься за игрока не может.

**Честная оговорка.** Владелец узла, на котором крутится бот, технически видит
все роли. Для дружеской игры разумнее всего, чтобы он в партии не участвовал.

Из ролей взяты только классические три: мафия, комиссар, мирные. Доктор,
любовница и прочее сознательно опущены — каждая добавленная роль удваивает
число ночных взаимодействий, а базовая игра работает и без них.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from enum import Enum
from random import Random

from .api import Action, Finish, GameError, Say, Whisper

NIGHT_TIMEOUT = 120.0
DAY_TIMEOUT = 240.0
VOTE_TIMEOUT = 120.0

MAFIA = "мафия"
DETECTIVE = "комиссар"
CIVILIAN = "мирный"


class Phase(Enum):
    NIGHT = "ночь"
    DAY = "день"
    VOTE = "голосование"


class Mafia:
    name = "мафия"
    title = "Мафия"
    min_players = 4
    max_players = 8
    verbs = frozenset({"убить", "проверить", "голос", "статус", "день"})

    def __init__(self, rng: Random) -> None:
        self._rng = rng
        self.roles: dict[str, str] = {}
        self.alive: list[str] = []
        self.phase = Phase.NIGHT
        self.round = 1
        self.finished = False
        self.deadline = 0.0

        self._kill_target: str | None = None
        self._checked_this_night = False
        self._votes: dict[str, str] = {}

    # --- каркас ---------------------------------------------------------------

    def start(self, players: Sequence[str]) -> list[Action]:
        self.alive = list(players)
        mafia_count = max(1, len(players) // 3)
        shuffled = list(players)
        self._rng.shuffle(shuffled)

        mafia = shuffled[:mafia_count]
        detective = shuffled[mafia_count]
        for player in players:
            if player in mafia:
                self.roles[player] = MAFIA
            elif player == detective:
                self.roles[player] = DETECTIVE
            else:
                self.roles[player] = CIVILIAN

        actions: list[Action] = [
            Say(
                f"Партия на {len(players)}: мафии {mafia_count}, комиссар один, "
                "остальные мирные.\n"
                "Ночные ходы пишите боту ЛИЧНО: /w <ник бота> !убить <ник>\n"
                "Если написать то же самое в общий чат — ход увидят все."
            )
        ]
        for player in players:
            actions.append(Whisper(player, self._role_card(player)))
        actions.append(self._begin_night())
        return actions

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        if verb == "статус":
            return [Whisper(player, self.snapshot_for(player))]
        if self.finished:
            raise GameError("партия окончена")
        if player not in self.alive:
            raise GameError("мёртвые не участвуют")

        if verb == "убить":
            return self._night_kill(player, rest)
        if verb == "проверить":
            return self._night_check(player, rest)
        if verb == "день":
            return self._open_vote(player)
        return self._vote(player, rest)

    def on_leave(self, player: str) -> list[Action]:
        if self.finished or player not in self.alive:
            return []
        self.alive.remove(player)
        self._votes.pop(player, None)
        actions: list[Action] = [
            Say(f"{player} покинул город. Он был {self.roles[player]}.")
        ]
        ending = self._check_end()
        return actions + ending if ending else actions + self._maybe_resolve()

    def tick(self, now: float) -> list[Action]:
        if self.finished or now < self.deadline:
            return []
        if self.phase is Phase.NIGHT:
            if self._kill_target is None:
                return [Say("Мафия не определилась — ночь прошла спокойно.")] + self._dawn()
            return self._dawn()
        if self.phase is Phase.DAY:
            return self._open_vote(None)
        return self._count_votes(by_timeout=True)

    def snapshot_for(self, player: str) -> str:
        if not self.roles:
            return ""
        status = "жив" if player in self.alive else "мёртв"
        lines = [
            f"{self._role_card(player)}",
            f"Вы {status}. Сейчас {self.phase.value}, круг {self.round}.",
            f"Живые: {', '.join(self.alive)}",
        ]
        if self.phase is Phase.VOTE and self._votes:
            lines.append("Проголосовали: " + ", ".join(sorted(self._votes)))
        return "\n".join(lines)

    # --- ночь -----------------------------------------------------------------

    def _begin_night(self) -> Action:
        self.phase = Phase.NIGHT
        self._kill_target = None
        self._checked_this_night = False
        self.deadline = time.monotonic() + NIGHT_TIMEOUT
        return Say(
            f"— Ночь {self.round}. Город засыпает. Живых: {len(self.alive)} "
            f"({', '.join(self.alive)})\n"
            "Мафия: !убить <ник>. Комиссар: !проверить <ник>. Только личным сообщением боту."
        )

    def _night_kill(self, player: str, rest: str) -> list[Action]:
        if self.phase is not Phase.NIGHT:
            raise GameError("сейчас не ночь")
        if self.roles[player] != MAFIA:
            raise GameError("это ход мафии")
        target = self._target(rest)
        if self.roles[target] == MAFIA:
            raise GameError("свои своих не трогают")

        self._kill_target = target
        actions: list[Action] = [
            Whisper(other, f"{player} выбрал жертву: {target}")
            for other in self.alive
            if self.roles[other] == MAFIA and other != player
        ]
        actions.insert(0, Whisper(player, f"Принято: {target}."))
        return actions + self._maybe_resolve()

    def _night_check(self, player: str, rest: str) -> list[Action]:
        if self.phase is not Phase.NIGHT:
            raise GameError("сейчас не ночь")
        if self.roles[player] != DETECTIVE:
            raise GameError("это ход комиссара")
        if self._checked_this_night:
            raise GameError("проверка уже сделана этой ночью")
        target = self._target(rest)

        self._checked_this_night = True
        verdict = "мафия" if self.roles[target] == MAFIA else "не мафия"
        return [Whisper(player, f"{target}: {verdict}.")] + self._maybe_resolve()

    def _maybe_resolve(self) -> list[Action]:
        """Ночь кончается, когда все ночные роли отходили."""
        if self.phase is not Phase.NIGHT or self.finished:
            return []
        detective_alive = any(self.roles[p] == DETECTIVE for p in self.alive)
        if self._kill_target is None:
            return []
        if detective_alive and not self._checked_this_night:
            return []
        return self._dawn()

    def _dawn(self) -> list[Action]:
        victim = self._kill_target
        actions: list[Action] = []
        if victim in self.alive:
            self.alive.remove(victim)
            actions.append(Say(f"— Рассвет. {victim} убит. Он был {self.roles[victim]}."))
        else:
            actions.append(Say("— Рассвет. Все живы."))

        ending = self._check_end()
        if ending:
            return actions + ending

        self.phase = Phase.DAY
        self.deadline = time.monotonic() + DAY_TIMEOUT
        actions.append(
            Say(
                f"День {self.round}. Живые: {', '.join(self.alive)}\n"
                "Обсуждайте. Когда готовы — !день, чтобы перейти к голосованию."
            )
        )
        return actions

    # --- день и голосование ----------------------------------------------------

    def _open_vote(self, player: str | None) -> list[Action]:
        if self.phase is not Phase.DAY:
            raise GameError("голосование уже идёт или сейчас ночь")
        self.phase = Phase.VOTE
        self._votes = {}
        self.deadline = time.monotonic() + VOTE_TIMEOUT
        who = f"{player} открывает голосование" if player else "Время вышло"
        return [Say(f"{who}. Голосуйте: !голос <ник>. Живые: {', '.join(self.alive)}")]

    def _vote(self, player: str, rest: str) -> list[Action]:
        if self.phase is not Phase.VOTE:
            raise GameError("голосование ещё не открыто (!день)")
        target = self._target(rest)
        self._votes[player] = target
        actions: list[Action] = [Say(f"{player} голосует против {target} "
                                     f"({len(self._votes)}/{len(self.alive)})")]
        if len(self._votes) >= len(self.alive):
            actions += self._count_votes(by_timeout=False)
        return actions

    def _count_votes(self, *, by_timeout: bool) -> list[Action]:
        if self.finished:
            return []
        tally: dict[str, int] = {}
        for target in self._votes.values():
            tally[target] = tally.get(target, 0) + 1

        actions: list[Action] = []
        if not tally:
            actions.append(Say("Никто не проголосовал — день прошёл впустую."))
            self.round += 1
            return actions + [self._begin_night()]

        best = max(tally.values())
        leaders = sorted(name for name, count in tally.items() if count == best)
        if len(leaders) > 1:
            actions.append(Say(f"Ничья ({', '.join(leaders)}) — никого не казнят."))
        else:
            victim = leaders[0]
            self.alive.remove(victim)
            prefix = "Время вышло. " if by_timeout else ""
            actions.append(Say(f"{prefix}Город казнит {victim}. Он был {self.roles[victim]}."))
            ending = self._check_end()
            if ending:
                return actions + ending

        self.round += 1
        return actions + [self._begin_night()]

    # --- итог ------------------------------------------------------------------

    def _check_end(self) -> list[Action]:
        mafia = [p for p in self.alive if self.roles[p] == MAFIA]
        others = [p for p in self.alive if self.roles[p] != MAFIA]
        if not mafia:
            self.finished = True
            return [Finish("Мафия истреблена — победа города! " + self._reveal())]
        if len(mafia) >= len(others):
            self.finished = True
            return [Finish("Мафии больше или поровну — победа мафии. " + self._reveal())]
        return []

    def _reveal(self) -> str:
        return "Роли: " + ", ".join(f"{name} — {role}" for name, role in sorted(self.roles.items()))

    def _role_card(self, player: str) -> str:
        role = self.roles.get(player, "зритель")
        if role == MAFIA:
            partners = [p for p, r in self.roles.items() if r == MAFIA and p != player]
            tail = f" Ваши: {', '.join(partners)}." if partners else " Вы одни."
            return f"Ваша роль: МАФИЯ.{tail}"
        if role == DETECTIVE:
            return "Ваша роль: КОМИССАР. Ночью можно проверить одного: !проверить <ник>"
        return "Ваша роль: мирный житель. Ночью спите, днём разбирайтесь."

    def _target(self, rest: str) -> str:
        name = rest.strip()
        if not name:
            raise GameError("укажите ник")
        if name not in self.alive:
            raise GameError(f"«{name}» не среди живых: {', '.join(self.alive)}")
        return name
