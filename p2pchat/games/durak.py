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

from .api import Action, Finish, GameError, Say, Whisper
from .cards import Card, CardError, deck36, parse_card, render_hand, sort_hand

HAND_SIZE = 6
MAX_ON_TABLE = 6
TURN_TIMEOUT = 180.0


class Durak:
    name = "дурак"
    title = "Дурак (подкидной)"
    min_players = 2
    max_players = 6
    verbs = frozenset({"ход", "подкинуть", "бить", "взять", "пас", "стол", "рука"})

    def __init__(self, rng: Random) -> None:
        self._rng = rng
        self.deck: list[Card] = []
        self.trump = ""
        self.trump_card: Card | None = None
        self.hands: dict[str, list[Card]] = {}
        self.order: list[str] = []
        self.out: list[str] = []
        self.table: list[tuple[Card, Card | None]] = []
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
                f"Козырь: {self.trump_card} ({self.trump}). В колоде {len(self.deck)} карт.\n"
                f"Ходит {self._attacker()}, отбивается {self._defender()}.\n"
                "!ход <карта>, !подкинуть <карта>, !бить <своя> <по чужой>, !взять, !пас\n"
                "Руки видны только вам — и владельцу узла с ботом."
            )
        ]
        actions += [Whisper(player, self._hand_text(player)) for player in self.order]
        return actions

    def handle(self, player: str, verb: str, rest: str) -> list[Action]:
        if verb == "рука":
            return [Whisper(player, self._hand_text(player))]
        if verb == "стол":
            return [Whisper(player, self.render_table())]
        if self.finished:
            raise GameError("партия окончена")
        if player in self.out:
            raise GameError("вы уже вышли из игры")

        self._arm()
        if verb in ("ход", "подкинуть"):
            return self._attack(player, rest, first=verb == "ход")
        if verb == "бить":
            return self._defend(player, rest)
        if verb == "взять":
            return self._take(player)
        return self._pass(player)

    def on_leave(self, player: str) -> list[Action]:
        if self.finished or player not in self.hands or player in self.out:
            return []
        self.out.append(player)
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
        if player == self._defender():
            raise GameError("защищающийся не подкидывает")
        if first and self.table:
            raise GameError("ход уже сделан, подкидывайте: !подкинуть <карта>")
        if not first and not self.table:
            raise GameError("подкидывать нечего — сначала !ход")
        if first and player != self._attacker():
            raise GameError(f"первым ходит {self._attacker()}")

        card = self._card_from_hand(player, rest)
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

        self.hands[player].remove(card)
        self.table.append((card, None))
        self.passed.discard(player)
        return [
            Say(f"{player} кладёт {card}.\n{self.render_table()}"),
            Whisper(player, self._hand_text(player)),
        ]

    def _defend(self, player: str, rest: str) -> list[Action]:
        if player != self._defender():
            raise GameError(f"отбивается {self._defender()}")
        parts = rest.split()
        if len(parts) != 2:
            raise GameError("формат: !бить <своя карта> <карта на столе>")

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
            Say(f"{player} бьёт {target} картой {mine}.\n{self.render_table()}"),
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
        return [Say(f"{player} забирает {len(taken)} карт.")] + self._reset_round(taken=True)

    def _pass(self, player: str) -> list[Action]:
        if not self.table:
            raise GameError("пасовать нечего — ход не сделан")
        if player == self._defender():
            raise GameError("защищающийся не пасует: !бить или !взять")
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
                f"В колоде {len(self.deck)}."
            )
        )
        actions += [Whisper(player, self._hand_text(player)) for player in active]
        return actions

    def _refill(self) -> None:
        order = [self._attacker()] + [
            p for p in self._active() if p not in (self._attacker(), self._defender())
        ]
        if self._defender() in self._active():
            order.append(self._defender())
        for player in order:
            while self.deck and len(self.hands[player]) < HAND_SIZE:
                self.hands[player].append(self.deck.pop(0))

    # --- служебное --------------------------------------------------------------

    def render_table(self) -> str:
        if not self.table:
            return "Стол пуст."
        pairs = " | ".join(
            f"{laid}" + (f" ← {beat}" if beat else " ← ?") for laid, beat in self.table
        )
        return f"Стол: {pairs}   (козырь {self.trump})"

    def _hand_text(self, player: str) -> str:
        hand = self.hands.get(player, [])
        return (
            f"Ваша рука ({len(hand)}): {render_hand(sort_hand(hand, self.trump))}\n"
            f"Козырь {self.trump}, в колоде {len(self.deck)}."
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
        card = self._parse(text)
        if card not in self.hands.get(player, []):
            raise GameError(f"{card} нет у вас на руках")
        return card

    def _arm(self) -> None:
        self.deadline = time.monotonic() + TURN_TIMEOUT
