"""
Terminal UI using curses. Отвечает за отрисовку, ввод и управление историей.
Не занимается сетью — только интерфейс.
"""

import curses
from collections import deque
from typing import Optional, List, Dict

from ui.message_model import Message
from ui.colors import (
    init_colors,
    get_nickname_color_index,
    get_color_pair,
    PAIR_SYSTEM_MSG,
    PAIR_PROMPT,
    PAIR_STATUS_BAR,
)
from utils.logging_config import get_logger

logger = get_logger(__name__)


# Конфигурация UI (не магические числа)
MAX_MESSAGES = 500
INPUT_WIN_HEIGHT = 3
MAX_VISIBLE_USERS = 10
MAX_INPUT_PROMPT = "[@                    ] "  # для расчёта ширины


class ChatUI:
    """
    Текстовый интерфейс чата на curses.

    Управляет:
    - Историей сообщений (с автоскроллом)
    - Строкой ввода (с базовым редактированием)
    - Статус-баром (статус + список онлайна)
    - Цветовым кодированием ников
    """

    def __init__(self, stdscr, my_nickname: str):
        self.stdscr = stdscr
        self.my_nickname = my_nickname
        self.messages: deque[Message] = deque(maxlen=MAX_MESSAGES)
        self.input_buffer = ""
        self.cursor_pos = 0
        self.running = True
        self.connected = False
        self.status_text = "Disconnected"
        self.online_users: List[str] = []

        # Маппинг ников на имена цветов (заполняется лениво)
        self._nickname_color_map: Dict[str, str] = {}

        # Инициализация curses
        curses.curs_set(0)  # Скрываем курсор
        self.stdscr.nodelay(True)  # Неблокирующий ввод
        curses.use_default_colors()  # Прозрачный фон
        init_colors()  # Наши цветовые пары

        # Размеры терминала
        self.max_y, self.max_x = self.stdscr.getmaxyx()

        # Окна: история + ввод
        self._init_windows()

        # Первая отрисовка
        self._redraw()
        logger.debug("ChatUI initialized for user '%s', terminal %dx%d",
                     my_nickname, self.max_x, self.max_y)

    def _init_windows(self) -> None:
        """Создаёт подсвеченные окна curses."""
        self.history_win = curses.newwin(self.max_y - INPUT_WIN_HEIGHT, self.max_x, 0, 0)
        self.history_win.scrollok(True)
        self.input_win = curses.newwin(INPUT_WIN_HEIGHT, self.max_x, self.max_y - INPUT_WIN_HEIGHT, 0)

    def add_message(self, text: str, sender: str, nickname: str = "") -> None:
        """Добавляет пользовательское сообщение в историю."""
        self.messages.append(Message(text=text, sender=sender, nickname=nickname))
        self._redraw()

    def add_system(self, text: str) -> None:
        """Добавляет системное сообщение и обновляет статус."""
        self.messages.append(Message(text=text, sender='system', nickname='***'))
        self.status_text = text
        self._redraw()

    def update_users(self, users: List[str]) -> None:
        """Обновляет список пользователей онлайн."""
        self.online_users = users
        self._redraw()

    def _redraw(self) -> None:
        """Полная перерисовка всех окон."""
        self._draw_history()
        self._draw_status_bar()
        self._draw_input()

        self.history_win.refresh()
        self.input_win.refresh()

    def _draw_history(self) -> None:
        """Отрисовывает историю сообщений с автоскроллом."""
        self.history_win.clear()

        display_msgs = list(self.messages)
        available_lines = self.max_y - INPUT_WIN_HEIGHT - 1  # -1 под статус-бар
        start_idx = max(0, len(display_msgs) - available_lines)

        for i, msg in enumerate(display_msgs[start_idx:], start=0):
            try:
                self._draw_single_message(i, msg)
            except curses.error:
                # Терминал слишком мал, похуй
                pass

    def _draw_single_message(self, row: int, msg: Message) -> None:
        """Отрисовывает одно сообщение."""
        if msg.is_system:
            text = f"  *** {msg.text}"[:self.max_x - 1]
            self.history_win.addstr(row, 0, text, curses.color_pair(PAIR_SYSTEM_MSG))
            return

        timestamp = msg.format_timestamp()

        # Временная метка (тусклая)
        self.history_win.addstr(row, 0, timestamp, curses.A_DIM)

        # [nickname] с цветом и жирным
        bracket_start = len(timestamp) + 1
        nick_str = f"[{msg.nickname}]"
        color_name = get_nickname_color_index(msg.nickname, self._nickname_color_map)
        color_attr = curses.color_pair(get_color_pair(color_name)) | curses.A_BOLD
        self.history_win.addstr(row, bracket_start, nick_str, color_attr)

        # Текст сообщения
        msg_start = bracket_start + len(nick_str) + 2
        if msg_start < self.max_x:
            remaining = self.max_x - msg_start - 1
            self.history_win.addstr(row, msg_start, msg.text[:remaining])

    def _draw_status_bar(self) -> None:
        """Отрисовывает статус-бар со списком онлайна."""
        status_row = self.max_y - INPUT_WIN_HEIGHT - 1

        # Формируем строку пользователей
        users_str = ", ".join(f"@{u}" for u in self.online_users[:MAX_VISIBLE_USERS])
        if len(self.online_users) > MAX_VISIBLE_USERS:
            users_str += f" +{len(self.online_users) - MAX_VISIBLE_USERS} more"

        status_line = f"[ {self.status_text} ]  Online: {users_str}"[:self.max_x - 1]

        try:
            self.history_win.addstr(
                status_row, 0, status_line,
                curses.color_pair(PAIR_STATUS_BAR) | curses.A_REVERSE
            )
        except curses.error:
            pass

    def _draw_input(self) -> None:
        """Отрисовывает строку ввода с промптом."""
        self.input_win.clear()
        self.input_win.box()

        try:
            prompt = f"[@{self.my_nickname}] "
            self.input_win.addstr(1, 1, prompt, curses.color_pair(PAIR_PROMPT) | curses.A_BOLD)

            max_input = self.max_x - len(prompt) - 3  # 3: рамка и пробелы
            if max_input > 0:
                # Показываем последние max_input символов, если буфер большой
                input_text = self.input_buffer[-max_input:] if len(self.input_buffer) > max_input else self.input_buffer
                self.input_win.addstr(1, len(prompt) + 1, input_text, curses.A_BOLD)
        except curses.error:
            pass

    def get_input_char(self) -> Optional[int]:
        """Возвращает код нажатой клавиши или None."""
        return self.stdscr.getch()

    def handle_input(self, key: int) -> Optional[str]:
        """
        Обрабатывает ввод с клавиатуры.

        Returns:
            Готовое сообщение для отправки (после Enter), или None.
        """
        if key == curses.ERR:
            return None

        # Enter — отправка
        if key in (ord('\n'), 10):
            msg = self.input_buffer.strip()
            self.input_buffer = ""
            self.cursor_pos = 0
            self._redraw()
            return msg if msg else None

        # Backspace / Delete
        elif key in (curses.KEY_BACKSPACE, 127, ord('\b')):
            if self.cursor_pos > 0:
                self.input_buffer = (
                    self.input_buffer[:self.cursor_pos - 1] +
                    self.input_buffer[self.cursor_pos:]
                )
                self.cursor_pos -= 1
                self._redraw()
            return None

        # Стрелки и навигация
        elif key == curses.KEY_LEFT:
            self.cursor_pos = max(0, self.cursor_pos - 1)
            self._redraw()
            return None

        elif key == curses.KEY_RIGHT:
            self.cursor_pos = min(len(self.input_buffer), self.cursor_pos + 1)
            self._redraw()
            return None

        elif key == curses.KEY_HOME:
            self.cursor_pos = 0
            self._redraw()
            return None

        elif key == curses.KEY_END:
            self.cursor_pos = len(self.input_buffer)
            self._redraw()
            return None

        # Печатные символы
        elif 32 <= key <= 126:
            self.input_buffer = (
                self.input_buffer[:self.cursor_pos] +
                chr(key) +
                self.input_buffer[self.cursor_pos:]
            )
            self.cursor_pos += 1
            self._redraw()
            return None

        # Неизвестная клавиша — игнорируем
        self._redraw()
        return None

    def resize(self) -> None:
        """Обрабатывает изменение размера терминала."""
        self.max_y, self.max_x = self.stdscr.getmaxyx()
        self._init_windows()  # Пересоздаём окна с новыми размерами
        self._redraw()
        logger.debug("Terminal resized to %dx%d", self.max_x, self.max_y)

    def clear_history(self) -> None:
        """Очищает историю сообщений."""
        self.messages.clear()
        self._redraw()
