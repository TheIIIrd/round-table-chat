"""
Security utilities: sanitization, forbidden nicknames, message validation.
"""

import re
from typing import Tuple


# Максимальная длина текста сообщения
MAX_MESSAGE_LENGTH = 10000

# Управляющие символы, которые могут поломать TUI (кроме \n, \t)
CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Запрещённые ники (служебные, вводящие в заблуждение)
FORBIDDEN_NICKNAMES: set[str] = {
    'admin', 'administrator', 'root', 'system', 'server',
    'null', 'undefined', 'none', 'true', 'false',
    'moderator', 'mod', 'owner', 'staff',
    'chat', 'bot', 'service',
    'everyone', 'all', 'here', 'channel',
}


def sanitize_message(text: str) -> Tuple[bool, str]:
    """
    Проверяет и очищает текст сообщения.

    Returns:
        (True, sanitized_text) — всё ок
        (False, error_message) — сообщение невалидно
    """
    if not text or not text.strip():
        return False, "Message cannot be empty"

    if len(text) > MAX_MESSAGE_LENGTH:
        return False, f"Message too long (max {MAX_MESSAGE_LENGTH} chars)"

    # Убираем управляющие символы
    sanitized = CONTROL_CHARS_PATTERN.sub('', text)

    if not sanitized.strip():
        return False, "Message contains only control characters"

    return True, sanitized


def is_nickname_forbidden(nickname: str) -> bool:
    """
    Проверяет, что ник не входит в список запрещённых.
    Сравнение без учёта регистра.
    """
    return nickname.lower() in FORBIDDEN_NICKNAMES


def get_nickname_error(nickname: str) -> str | None:
    """
    Возвращает текст ошибки, если ник невалиден, иначе None.
    Объединяет все проверки ника в одном месте.
    """
    if not nickname or not nickname.strip():
        return "Nickname cannot be empty"

    if len(nickname) < 1 or len(nickname) > 20:
        return "Nickname must be 1-20 characters"

    if not re.match(r'^[a-zA-Z0-9_\-]+$', nickname):
        return "Nickname must contain only a-z, A-Z, 0-9, _, -"

    if is_nickname_forbidden(nickname):
        return f"Nickname '{nickname}' is reserved"

    return None
