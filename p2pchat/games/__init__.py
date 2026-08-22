"""Игры для чата.

Добавить свою — три шага: написать класс по контракту из ``api.py``, положить
файл в этот каталог, дописать строку в ``CATALOG``. Ни бота, ни меша, ни сети
трогать не нужно.
"""

from __future__ import annotations

import secrets
from random import Random

from .api import Action, Finish, Game, GameError, Say, Whisper
from .connect_four import ConnectFour
from .durak import Durak
from .hangman import Hangman
from .lobby import GameHost, Phase
from .mafia import Mafia

CATALOG: dict[str, type] = {
    ConnectFour.name: ConnectFour,
    Durak.name: Durak,
    Hangman.name: Hangman,
    Mafia.name: Mafia,
}


def build_host(rng: Random | None = None) -> GameHost:
    return GameHost(catalog=dict(CATALOG), rng=rng or Random(secrets.randbits(64)))


__all__ = [
    "Action",
    "CATALOG",
    "ConnectFour",
    "Durak",
    "Hangman",
    "Mafia",
    "Finish",
    "Game",
    "GameError",
    "GameHost",
    "Phase",
    "Say",
    "Whisper",
    "build_host",
]
