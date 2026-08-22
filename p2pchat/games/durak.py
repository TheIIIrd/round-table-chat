"""Подкидной дурак на 2–6 игроков.

Правила взяты в устоявшемся объёме: 36 карт, козырь по нижней карте колоды,
первым ходит обладатель младшего козыря, подкидывать может любой игрок картой
того же достоинства, что уже лежит на столе, добор до шести после каждого
круга, вышедшие из карт выбывают, последний с картами — дурак.

Что **не** реализовано и почему: перевод (переброс атаки соседу) и «погоны»
меняют очерёдность и требуют отдельного согласования правил в компании, а
половинчатая реализация спорных правил хуже их отсутствия. На столе не больше шести карт
за круг, и подкинуть нельзя больше, чем защищающийся способен отбить.

Руки раздаются через ``Whisper``, то есть в личную сессию каждого игрока.
Владелец узла с ботом при этом видит все руки — предупреждение выводится при
раздаче.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from random import Random

from ..format import panel, plural
from .api import Action, Finish, GameError, Say, Whisper
from .cards import Card, CardError, deck36, parse_card, render_hand, resolve_in_hand, sort_hand

HAND_SIZE = 6
MAX_ON_TABLE = 6
TURN_TIMEOUT = 180.0


class Durak:
    name = "durak"
    title = "Дурак (подкидной)"
    min_players = 2
    max_players = 6
    verbs = frozenset({"attack", "add", "beat", "take", "pass", "table", "hand"})
    aliases = {
        "ход": "attack",
        "подкинуть": "add",
        "бить": "beat",
        "взять": "take",
        "пас": "pass",
        "стол": "table",
        "рука": "hand",
    }

    def __init__(self, rng: Random) -> None:
        self._rng = rng
        self.deck: list[Card] = []
        self.trump = ""
        self.trump_card: Card | None = None
        self.hands: dict[str, list[Card]] = {}
        self.order: list[str] = []
        self.out: list[str] = []
        self.table: list[tuple[Card, Card | None]] = []
        # Отбой: карты, вышедшие из игры. Раньше их просто выбрасывали, и колода
        # переставала сходиться — 36 карт превращались в 34, потом в 30. На игру
        # это не влияло, но проверить целостность было нечем, а игрокам в
        # концовке важно знать, сколько уже вышло.
        self.discarded: list[Card] = []
        self.attacker = 0
        self.defender = 1
        self.passed: set[str] = set()
        self.finished = False
        self.deadline = 0.0

    # --- каркас ---------------------------------------------------------------

    def start(self, players: Sequence[str]) -> list[Action]:
        self.order = list(players)
        self.deck = deck36(self._rng)
        self.trump_card = self.deck[-1]
        self.trump = self.trump_card.suit

        for player in self.order:
            self.hands[player] = []
        for _ in range(HAND_SIZE):
            for player in self.order:
                self.hands[player].append(self.deck.pop(0))

        self.attacker = self._lowest_trump_holder()
        self.defender = (self.attacker + 1) % len(self.order)
        self._arm()

        actions: list[Action] = [
            Say(
                f"Козырь: {self.trump_card} ({self.trump}). "
                f"В колоде {len(self.deck)} карт.\n"
                f"Ходит {self._attacker()}, отбивается {self._defender()}.\n"
                "!attack <карта>, !add <карта>, !beat <своя> <чужая>, !take, !pass, !hand\n"
                "Руки видны только вам — и владельцу узла с ботом."
            )
        ]
        actions += [Whisper(player, self._hand_text(player)) for player in self.order]
        return actions

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        if verb == "hand":
            return [Whisper(player, self._hand_text(player))]
        if verb == "table":
            return [Whisper(player, self.render_table(with_hints=True))]
        if self.finished:
            raise GameError("партия окончена")
        if player in self.out:
            raise GameError("вы уже вышли из игры")

        self._arm()
        if verb in ("attack", "add"):
            return self._attack(player, rest, first=verb == "attack")
        if verb == "beat":
            return self._defend(player, rest)
        if verb == "take":
            return self._take(player)
        return self._pass(player)

    def on_leave(self, player: str) -> list[Action]:
        if self.finished or player not in self.hands or player in self.out:
            return []
        self.out.append(player)
        # Карты ушедшего уходят в отбой. Иначе они остаются «на руках» у того,
        # кого уже нет за столом: колода сходится по счёту, но состояние врёт —
        # выбывший держит карты, которых никто не может сыграть.
        self.discarded.extend(self.hands[player])
        self.hands[player] = []
        remaining = [p for p in self.order if p not in self.out]
        if len(remaining) <= 1:
            self.finished = True
            tail = f" Дураком остался {remaining[0]}." if remaining else ""
            return [Finish(f"{player} ушёл, играть не с кем.{tail}")]
        return [Say(f"{player} ушёл из партии.")] + self._reset_round(taken=False)

    def tick(self, now: float) -> list[Action]:
        if self.finished or now < self.deadline:
            return []
        self.finished = True
        return [Finish("Никто не ходит уже три минуты — партия отменена.")]

    def snapshot_for(self, player: str) -> str:
        if not self.hands:
            return ""
        return f"{self._hand_text(player)}\n{self.render_table()}"

    # --- ходы ------------------------------------------------------------------

    def _attack(self, player: str, rest: str, *, first: bool) -> list[Action]:
        """Кладёт одну или несколько карт.

        Несколько за раз — не роскошь: подкидывать по одной, дожидаясь эха от
        бота, в чате мучительно. `!attack 6♥ 6♣` кладёт обе, если правила
        позволяют; если вторая не проходит — первая остаётся на столе, а игрок
        получает объяснение по второй.
        """
        if player == self._defender():
            raise GameError("защищающийся не подкидывает: !beat или !take")
        if first and self.table:
            raise GameError("ход уже сделан, подкидывайте: !add <карта>")
        if not first and not self.table:
            raise GameError("подкидывать нечего — сначала !attack")
        if first and player != self._attacker():
            raise GameError(f"первым ходит {self._attacker()}")

        tokens = rest.split()
        if not tokens:
            raise GameError("укажите карту: !attack <карта>")

        placed: list[Card] = []
        problem = ""
        for token in tokens:
            try:
                card = self._card_from_hand(player, token)
                self._check_can_place(card)
            except GameError as exc:
                problem = str(exc)
                break
            self.hands[player].remove(card)
            self.table.append((card, None))
            placed.append(card)

        if not placed:
            raise GameError(problem)

        self.passed.discard(player)
        laid = ", ".join(str(card) for card in placed)
        text = f"{player} кладёт {laid}."
        if problem:
            text += f" (дальше нельзя: {problem})"
        return [
            Say(f"{text}\n{self.render_table(with_hints=True)}"),
            Whisper(player, self._hand_text(player)),
        ]

    def _check_can_place(self, card: Card) -> None:
        """Проверяет, можно ли положить карту на стол прямо сейчас."""
        if self.table:
            ranks = {laid.rank for laid, _ in self.table}
            ranks |= {beat.rank for _, beat in self.table if beat is not None}
            if card.rank not in ranks:
                raise GameError(f"{card} подкинуть нельзя: на столе нет такого достоинства")

        if len(self.table) >= MAX_ON_TABLE:
            raise GameError(f"на столе уже {MAX_ON_TABLE} карт — предел")
        undefended = sum(1 for _, beat in self.table if beat is None)
        if undefended >= len(self.hands[self._defender()]):
            raise GameError(f"{self._defender()} нечем отбиваться — больше не подкинуть")

    def _defend(self, player: str, rest: str) -> list[Action]:
        if player != self._defender():
            raise GameError(f"отбивается {self._defender()}")
        parts = rest.split()
        if len(parts) != 2:
            raise GameError("формат: !beat <своя карта> <карта на столе>")

        mine = self._card_from_hand(player, parts[0])
        target = self._parse(parts[1])
        for index, (laid, beat) in enumerate(self.table):
            if laid == target and beat is None:
                if not mine.beats(laid, self.trump):
                    raise GameError(f"{mine} не бьёт {laid}")
                self.hands[player].remove(mine)
                self.table[index] = (laid, mine)
                break
        else:
            raise GameError(f"{target} нет на столе среди неотбитых")

        actions: list[Action] = [
            Say(f"{player} бьёт {target} картой {mine}.\n{self.render_table(with_hints=True)}"),
            Whisper(player, self._hand_text(player)),
        ]
        if all(beat is not None for _, beat in self.table) and not self.hands[player]:
            return actions + self._reset_round(taken=False)
        return actions

    def _take(self, player: str) -> list[Action]:
        if player != self._defender():
            raise GameError("взять карты может только защищающийся")
        if not self.table:
            raise GameError("со стола нечего брать")
        taken = [card for pair in self.table for card in pair if card is not None]
        self.hands[player].extend(taken)
        word = plural(len(taken), "карту", "карты", "карт")
        return [Say(f"{player} забирает {len(taken)} {word}.")] + self._reset_round(taken=True)

    def _pass(self, player: str) -> list[Action]:
        if not self.table:
            raise GameError("пасовать нечего — ход не сделан")
        if player == self._defender():
            raise GameError("защищающийся не пасует: !beat или !take")
        if any(beat is None for _, beat in self.table):
            raise GameError(f"{self._defender()} ещё не отбился")

        self.passed.add(player)
        attackers = {p for p in self._active() if p != self._defender()}
        if not attackers - self.passed:
            return [Say("Бито.")] + self._reset_round(taken=False)
        return [Say(f"{player} пасует ({len(self.passed)}/{len(attackers)}).")]

    # --- круг ------------------------------------------------------------------

    def _reset_round(self, *, taken: bool) -> list[Action]:
        defender = self._defender()
        if not taken:
            self.discarded.extend(
                card for pair in self.table for card in pair if card is not None
            )
        self.table = []
        self.passed = set()

        actions: list[Action] = []
        self._refill()

        for player in list(self.order):
            if not self.hands.get(player) and not self.deck and player not in self.out:
                self.out.append(player)
                actions.append(Say(f"{player} вышел из игры."))

        active = self._active()
        if len(active) <= 1:
            self.finished = True
            tail = f"Дурак — {active[0]}." if active else "Ничья: все вышли одновременно."
            return actions + [Finish(tail)]

        # Следующий атакующий: защитившийся ходит сам, забравший — пропускает.
        anchor = defender if not taken else self._next_active(defender)
        if anchor not in active:
            anchor = self._next_active(defender)
        self.attacker = self.order.index(anchor)
        self.defender = self.order.index(self._next_active(anchor))
        self._arm()

        actions.append(
            Say(
                f"Ходит {self._attacker()}, отбивается {self._defender()}. "
                f"В колоде {len(self.deck)}.\n" + self._hints_line()
            )
        )
        actions += [Whisper(player, self._hand_text(player)) for player in active]
        return actions

    def _refill(self) -> None:
        """Добор до шести: сначала атакующий, потом остальные, защищающийся последним.

        Порядок берётся по ролям ЗАВЕРШИВШЕГОСЯ круга — так правильно. Но роли
        нужно фильтровать по составу: прежний атакующий мог только что выбыть
        или уйти, и без проверки добор возвращал карты тому, кого за столом уже
        нет.
        """
        active = self._active()
        order = [player for player in (self._attacker(),) if player in active]
        order += [p for p in active if p not in (self._attacker(), self._defender())]
        if self._defender() in active:
            order.append(self._defender())
        for player in order:
            while self.deck and len(self.hands[player]) < HAND_SIZE:
                self.hands[player].append(self.deck.pop(0))

    # --- служебное --------------------------------------------------------------

    def render_table(self, with_hints: bool = False) -> str:
        body = (
            " ".join(f"{laid}/{beat}" if beat else f"{laid}/·" for laid, beat in self.table)
            if self.table
            else "(пусто)"
        )
        table = panel(
            body,
            title=f"Стол · козырь {self.trump}",
            footer=f"колода {len(self.deck)}",
        )
        hints = self._hints_line() if with_hints else ""
        return f"{table}\n{hints}" if hints else table

    def _hand_text(self, player: str) -> str:
        hand = self.hands.get(player, [])
        return panel(
            render_hand(sort_hand(hand, self.trump)),
            title=f"Ваша рука ({len(hand)})",
            footer=(
                f"козырь {self.trump} · колода {len(self.deck)} · отбой {len(self.discarded)}"
            ),
        )

    def _active(self) -> list[str]:
        return [p for p in self.order if p not in self.out]

    def _attacker(self) -> str:
        return self.order[self.attacker]

    def _defender(self) -> str:
        return self.order[self.defender]

    def _next_active(self, player: str) -> str:
        index = self.order.index(player)
        for step in range(1, len(self.order) + 1):
            candidate = self.order[(index + step) % len(self.order)]
            if candidate not in self.out:
                return candidate
        return player

    def _lowest_trump_holder(self) -> int:
        best_player, best_value = None, 99
        for index, player in enumerate(self.order):
            for card in self.hands[player]:
                if card.suit == self.trump and card.value() < best_value:
                    best_player, best_value = index, card.value()
        return best_player if best_player is not None else 0

    def _parse(self, text: str) -> Card:
        try:
            return parse_card(text)
        except CardError as exc:
            raise GameError(str(exc)) from exc

    def _card_from_hand(self, player: str, text: str) -> Card:
        try:
            return resolve_in_hand(text, self.hands.get(player, []))
        except CardError as exc:
            raise GameError(str(exc)) from exc

    def _hints_for(self, player: str) -> str:
        """Что этот игрок может сделать прямо сейчас."""
        if self.finished or player in self.out:
            return ""
        if player == self._defender():
            undefended = [laid for laid, beat in self.table if beat is None]
            if not undefended:
                return "ждёте: подкинут или скажут «бито»"
            return f"!beat <своя> {undefended[0]}   !take   !hand"
        if not self.table:
            return "!attack <карта>   !hand" if player == self._attacker() else "ждёте хода"
        if any(beat is None for _, beat in self.table):
            return "!add <карта>, ждём защиту"
        return "!add <карта>   !pass"

    def _hints_line(self) -> str:
        parts = [
            f"{player}: {hint}"
            for player in self._active()
            if (hint := self._hints_for(player))
        ]
        return "\n".join(parts)

    def _arm(self) -> None:
        self.deadline = time.monotonic() + TURN_TIMEOUT
