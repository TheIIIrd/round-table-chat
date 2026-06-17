"""
Validators for user input and addresses.
Вся валидация в одном месте, чтобы не размазывать regex'ы по коду.
"""

import re
from typing import Tuple, Optional

from utils.security import is_nickname_forbidden


# Константы валидации (вдруг захочешь разрешить emoji в никах, хех)
NICKNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,20}$')
NICKNAME_MIN_LENGTH = 1
NICKNAME_MAX_LENGTH = 20

# host:port или ip:port
PEER_ADDR_PATTERN = re.compile(
    r'^(.+):(\d{1,5})$'  # host:port, порт валидируем отдельно
)


def validate_nickname(nickname: str) -> Tuple[bool, Optional[str]]:
    """
    Проверяет никнейм на валидность.

    Returns:
        (True, None) — ник валиден
        (False, "описание ошибки") — что-то не так
    """
    if not nickname:
        return False, "Nickname cannot be empty"

    if len(nickname) < NICKNAME_MIN_LENGTH:
        return False, f"Nickname too short (min {NICKNAME_MIN_LENGTH} char)"

    if len(nickname) > NICKNAME_MAX_LENGTH:
        return False, f"Nickname too long (max {NICKNAME_MAX_LENGTH} chars)"

    if not NICKNAME_PATTERN.match(nickname):
        return False, "Nickname must contain only a-z, A-Z, 0-9, _, -"

    if is_nickname_forbidden(nickname):
        return False, f"Nickname '{nickname}' is reserved"

    return True, None


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """Проверяет, что порт в диапазоне 1-65535."""
    if not isinstance(port, int):
        return False, "Port must be an integer"
    if port < 1 or port > 65535:
        return False, f"Port must be between 1 and 65535, got {port}"
    return True, None


def parse_peer_address(addr: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Парсит строку вида 'host:port'.

    Returns:
        (host, port, None) — успешно
        (None, None, "ошибка") — невалидный формат
    """
    match = PEER_ADDR_PATTERN.match(addr)
    if not match:
        return None, None, f"Invalid address format: '{addr}'. Expected host:port"

    host = match.group(1)
    try:
        port = int(match.group(2))
    except ValueError:
        return None, None, f"Invalid port number in '{addr}'"

    is_valid, error = validate_port(port)
    if not is_valid:
        return None, None, error

    return host, port, None
