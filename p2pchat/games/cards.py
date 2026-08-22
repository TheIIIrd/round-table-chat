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
# Люди называют масти по-разному («трефы» и «крести», «бубны» и «буби») и
# промахиваются раскладкой: латинская p похожа на п, B на В. Отказывать из-за
# этого — худшее, что может сделать игра, поэтому принимаем все варианты.
SUIT_ALIASES = {
    "♠": "♠", "п": "♠", "s": "♠", "p": "♠",
    "♥": "♥", "ч": "♥", "h": "♥",
    "♦": "♦", "б": "♦", "d": "♦",
    "♣": "♣", "т": "♣", "к": "♣", "c": "♣", "k": "♣",
}

RANKS_36 = ("6", "7", "8", "9", "10", "В", "Д", "К", "Т")
# «к» и «к» — беда: это и король, и крести. Достоинство разбирается раньше
# масти и только из начала строки, поэтому «Кч» — король червей, а «6к» —
# шестёрка крестей; неоднозначности не возникает.
RANK_ALIASES = {
    "j": "В", "в": "В", "b": "В",
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


def parse_rank(text: str, ranks: tuple[str, ...] = RANKS_36) -> str | None:
    """Разбирает одно достоинство без масти: «10», «т», «в»."""
    raw = text.strip().lower()
    if not raw:
        return None
    rank = RANK_ALIASES.get(raw, raw.upper() if raw != "10" else "10")
    return rank if rank in ranks else None


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


def resolve_in_hand(text: str, hand: Sequence[Card], ranks: tuple[str, ...] = RANKS_36) -> Card:
    """Находит карту в руке по описанию, допуская сокращения.

    Если достоинство в руке одно — масть указывать не нужно: «!attack 10»
    сыграет единственную десятку. Если их несколько, игра не гадает, а
    перечисляет варианты: угаданная не та карта хуже переспроса.
    """
    text = text.strip()
    if not text:
        raise CardError("не указана карта")

    try:
        card = parse_card(text, ranks)
    except CardError:
        card = None

    if card is not None:
        if card not in hand:
            raise CardError(f"{card} нет у вас на руках")
        return card

    rank = parse_rank(text, ranks)
    if rank is None:
        raise CardError(f"«{text}» не похоже на карту")

    matches = [item for item in hand if item.rank == rank]
    if not matches:
        raise CardError(f"карт достоинства {rank} у вас нет")
    if len(matches) > 1:
        options = " ".join(str(item) for item in matches)
        raise CardError(f"у вас несколько таких карт — уточните масть: {options}")
    return matches[0]


def deck36(rng: Random) -> list[Card]:
    cards = [Card(rank, suit) for suit in SUITS for rank in RANKS_36]
    rng.shuffle(cards)
    return cards


def sort_hand(cards: Iterable[Card], trump: str, ranks: tuple[str, ...] = RANKS_36) -> list[Card]:
    """Козыри в конец, внутри масти — по возрастанию: так руку удобно читать."""
    return sorted(cards, key=lambda card: (card.suit == trump, card.suit, card.value(ranks)))


def render_hand(cards: Iterable[Card]) -> str:
    return " ".join(str(card) for card in cards) or "(пусто)"
