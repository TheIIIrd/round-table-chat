"""Color management for chat TUI. Все палитры в одном месте."""

import curses
from typing import Dict, Tuple


# Цветовые пары: (curses_color, pair_id)
# pair_id должен совпадать с тем, что передаётся в curses.init_pair()
COLOR_POOL: Dict[str, Tuple[int, int]] = {
    'green':    (curses.COLOR_GREEN,    1),
    'cyan':     (curses.COLOR_CYAN,     2),
    'yellow':   (curses.COLOR_YELLOW,   3),
    'magenta':  (curses.COLOR_MAGENTA,  4),
    'blue':     (curses.COLOR_BLUE,     5),
    'red':      (curses.COLOR_RED,      6),
    'white':    (curses.COLOR_WHITE,    7),
}

# Порядок цветов для ников (чтобы каждый новый ник получал следующий цвет)
NICKNAME_COLORS = ['green', 'cyan', 'magenta', 'blue', 'red', 'white']

# Пары для специальных элементов UI
PAIR_SYSTEM_MSG = 3     # yellow — системные сообщения
PAIR_PROMPT = 4         # magenta — промпт ввода
PAIR_STATUS_BAR = 3     # yellow — статус-бар (reverse)


def init_colors() -> None:
    """
    Инициализирует все цветовые пары curses.
    Должна вызываться один раз при старте UI.
    """
    for color_name, (color, pair_id) in COLOR_POOL.items():
        curses.init_pair(pair_id, color, -1)  # -1 — использовать дефолтный фон терминала


def get_nickname_color_index(nickname: str, color_map: Dict[str, str]) -> str:
    """
    Возвращает имя цвета для ника.

    Args:
        nickname: ник пользователя
        color_map: словарь {nickname: color_name} для уже назначенных цветов

    Returns:
        имя цвета из COLOR_POOL
    """
    if nickname not in color_map:
        idx = len(color_map) % len(NICKNAME_COLORS)
        color_map[nickname] = NICKNAME_COLORS[idx]
    return color_map[nickname]


def get_color_pair(color_name: str) -> int:
    """
    Возвращает ID цветовой пары curses по имени цвета.

    Пример:
        pair_id = get_color_pair('green')
        stdscr.addstr(0, 0, "text", curses.color_pair(pair_id))
    """
    return COLOR_POOL[color_name][1]
