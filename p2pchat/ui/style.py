"""Цвет в консоли.

Три правила, которым здесь всё подчиняется.

**Цвет добавляется только при выводе.** В сеть ANSI-последовательности не
уходят никогда: сообщение остаётся обычным текстом, а раскрашивает его клиент
получателя. Иначе один участник мог бы управлять терминалом другого.

**Цвет — не единственный носитель смысла.** Предупреждение остаётся
предупреждением и в чёрно-белом терминале: у него есть свой значок и слово.
Цвет только ускоряет чтение.

**Молчаливое отключение.** Не терминал, `NO_COLOR`, `TERM=dumb` или флаг
`--no-color` — и вывод становится обычным текстом без единой оговорки.

Цвет ника выводится из его публичного ключа, а не из имени: два участника с
похожими никами получат разные цвета, а подделать чужой цвет, представившись
его именем, невозможно — ключ другой.
"""

from __future__ import annotations

import hashlib
import os
import sys

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
ITALIC = "\x1b[3m"

# Палитра для ников: 256-цветный режим, без слишком тёмных и слишком блёклых.
NICK_COLORS = (39, 41, 43, 45, 75, 79, 81, 111, 113, 141, 147, 173, 175, 179, 209, 213)

RED = "\x1b[38;5;203m"
YELLOW = "\x1b[38;5;179m"
GREEN = "\x1b[38;5;114m"
BLUE = "\x1b[38;5;110m"
GREY = "\x1b[38;5;245m"
BOT = "\x1b[38;5;147m"


class Palette:
    """Обёртка, которая либо красит, либо возвращает текст как есть."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap(BOLD, text)

    def dim(self, text: str) -> str:
        return self._wrap(DIM, text)

    def red(self, text: str) -> str:
        return self._wrap(RED, text)

    def yellow(self, text: str) -> str:
        return self._wrap(YELLOW, text)

    def green(self, text: str) -> str:
        return self._wrap(GREEN, text)

    def blue(self, text: str) -> str:
        return self._wrap(BLUE, text)

    def grey(self, text: str) -> str:
        return self._wrap(GREY, text)

    def bot(self, text: str) -> str:
        return self._wrap(BOT, text)

    def alert(self, text: str) -> str:
        """Красное и жирное одной последовательностью.

        Вложенные вызовы (`red(bold(...))`) дают два подряд идущих сброса:
        визуально безвредно, но мусорно и мешает сравнивать вывод в тестах.
        """
        return self._wrap(RED + BOLD, text)

    def nick(self, name: str, public: bytes | None = None) -> str:
        if not self.enabled:
            return name
        material = public if public else name.encode("utf-8")
        index = hashlib.blake2s(b"nick-color" + material).digest()[0] % len(NICK_COLORS)
        return f"\x1b[38;5;{NICK_COLORS[index]}m{name}{RESET}"


def supports_color(stream=None, override: bool | None = None) -> bool:
    if override is not None:
        return override
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") in ("dumb", ""):
        return False
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def build_palette(override: bool | None = None) -> Palette:
    return Palette(supports_color(override=override))
