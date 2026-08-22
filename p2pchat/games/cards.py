"""Карты: то, что иначе каждая карточная игра изобретёт заново.

Разбор ввода намеренно снисходителен. Человек в чате напишет и `7ч`, и `7h`,
и `7♥`, и `10п`, и `Тт`. Отказывать ему из-за раскладки клавиатуры — плохая
идея, поэтому принимаются русские и латинские обозначения и символы мастей.

Тасовка идёт через переданный извне ``Random``: в бою он засеян из ``secrets``,
в тестах — фиксированным числом, иначе правила не проверить.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from random import Random

SUITS = ("♠", "♥", "♦", "♣")
SUIT_ALIASES = {
    "♠": "♠", "п": "♠", "s": "♠",
    "♥": "♥", "ч": "♥", "h": "♥",
    "♦": "♦", "б": "♦", "d": "♦",
    "♣": "♣", "т": "♣", "c": "♣",
}

RANKS_36 = ("6", "7", "8", "9", "10", "В", "Д", "К", "Т")
RANK_ALIASES = {
    "j": "В", "в": "В",
    "q": "Д", "д": "Д",
    "k": "К", "к": "К",
    "a": "Т", "т": "Т",
    "t": "10",
}


class CardError(Exception):
    """Строка не разбирается как карта."""


@dataclass(frozen=True, order=True)
class Card:
    rank: str
    suit: str

    def __str__(self) -> str:
        return f"{self.rank}{self.suit}"

    def value(self, ranks: tuple[str, ...] = RANKS_36) -> int:
        return ranks.index(self.rank)

    def beats(self, other: "Card", trump: str, ranks: tuple[str, ...] = RANKS_36) -> bool:
        """Бьёт ли эта карта другую при данном козыре."""
        if self.suit == other.suit:
            return self.value(ranks) > other.value(ranks)
        return self.suit == trump and other.suit != trump


def parse_card(text: str, ranks: tuple[str, ...] = RANKS_36) -> Card:
    raw = text.strip().replace(" ", "")
    if len(raw) < 2:
        raise CardError(f"«{text}» не похоже на карту")

    suit_key = raw[-1].lower()
    suit = SUIT_ALIASES.get(suit_key)
    if suit is None:
        raise CardError(f"не понял масть в «{text}» (пики п, черви ч, бубны б, трефы т)")

    rank_raw = raw[:-1].lower()
    rank = RANK_ALIASES.get(rank_raw, rank_raw.upper() if rank_raw != "10" else "10")
    if rank not in ranks:
        raise CardError(f"не понял достоинство в «{text}» (от {ranks[0]} до {ranks[-1]})")
    return Card(rank=rank, suit=suit)


def deck36(rng: Random) -> list[Card]:
    cards = [Card(rank, suit) for suit in SUITS for rank in RANKS_36]
    rng.shuffle(cards)
    return cards


def sort_hand(cards: Iterable[Card], trump: str, ranks: tuple[str, ...] = RANKS_36) -> list[Card]:
    """Козыри в конец, внутри масти — по возрастанию: так руку удобно читать."""
    return sorted(cards, key=lambda card: (card.suit == trump, card.suit, card.value(ranks)))


def render_hand(cards: Iterable[Card]) -> str:
    return " ".join(str(card) for card in cards) or "(пусто)"
