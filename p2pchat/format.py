"""Оформление текста, общее для бота и клиента.

Две разные задачи, которые важно не смешивать.

**Структура едет по проводу.** Рамки из псевдографики бот вставляет прямо в
текст сообщения: их видят все одинаково, независимо от терминала, и они
остаются читаемыми даже там, где цвета недоступны.

**Цвет накладывается локально.** ANSI-последовательности никогда не уходят в
сеть. Причина не только в совместимости: текст от собеседника — это данные от
постороннего, и если печатать его как есть, любой участник сможет прислать
`\\x1b[2J` и очистить вам экран, переставить курсор или подменить заголовок
окна. Поэтому всё входящее проходит через ``sanitize``.
"""

from __future__ import annotations

import re
import unicodedata

# Управляющие символы и ANSI-последовательности во входящем тексте.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

MAX_LINE = 200
MAX_LINES = 40
TAB_WIDTH = 4


def sanitize(text: str) -> str:
    """Убирает из чужого текста всё, чем можно управлять терминалом.

    Табуляция заменяется пробелами: она не опасна, но её ширину нельзя
    посчитать заранее — терминал растянет её до следующей позиции табуляции, и
    рамка вокруг такого текста разъедется, хотя по нашим меркам будет ровной.
    """
    cleaned = ANSI.sub("", text)
    cleaned = cleaned.replace("\t", " " * TAB_WIDTH)
    cleaned = CONTROL.sub("", cleaned)
    lines = [line[:MAX_LINE] for line in cleaned.split("\n")[:MAX_LINES]]
    return "\n".join(lines)


def strip_ansi(text: str) -> str:
    """Убирает последовательности цвета, оставляя сам текст."""
    return ANSI.sub("", text)


def clip_utf8(text: str, limit: int) -> bytes:
    """Кодирует строку в UTF-8, укладываясь в ``limit`` байт.

    Обрезка среза (``text.encode()[:limit]``) разрубает многобайтовый символ
    пополам, и получившиеся байты уже не декодируются. В кириллице это
    случается на ровном месте: тридцать три байта — это семнадцать букв.
    Оборванный хвост отбрасывается целиком.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return encoded
    return encoded[:limit].decode("utf-8", errors="ignore").encode("utf-8")


def width(text: str) -> int:
    """Ширина строки в знакоместах: широкие символы считаются за два."""
    total = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        total += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return total


def pad(text: str, target: int) -> str:
    return text + " " * max(0, target - width(text))


def panel(body: str, *, title: str = "", footer: str = "") -> str:
    """Заключает текст в рамку.

    Именно рамка, а не цвет, отделяет доску или расклад от потока реплик: она
    работает в любом терминале и переживает копирование в другой чат.
    """
    lines = body.rstrip("\n").split("\n")
    inner = max([width(line) for line in lines] + [width(title) + 2, width(footer) + 2, 10])

    # Ширина строки в рамке: «│ » + содержимое + « │» — то есть inner + 4.
    top = _edge("┌", "┐", title, inner)
    bottom = _edge("└", "┘", footer, inner)
    middle = [f"│ {pad(line, inner)} │" for line in lines]
    return "\n".join([top, *middle, bottom])


def _edge(left: str, right: str, label: str, inner: int) -> str:
    if not label:
        return left + "─" * (inner + 2) + right
    dashes = max(0, inner - width(label) - 1)
    return f"{left}─ {label} " + "─" * dashes + right


def plural(count: int, one: str, few: str, many: str) -> str:
    """Русское склонение после числительного: 1 карту, 2 карты, 5 карт."""
    tail_two = count % 100
    if 11 <= tail_two <= 14:
        return many
    tail = count % 10
    if tail == 1:
        return one
    if 2 <= tail <= 4:
        return few
    return many


def bullet(text: str) -> str:
    return f"• {text}"
