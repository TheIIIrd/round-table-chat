"""
Rate limiting for chat server.
Не даём одному мудаку заспамить весь чат или положить сервер.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class RateLimit:
    """Ограничение на частоту действий."""
    max_requests: int
    window_seconds: float
    requests: list[float] = field(default_factory=list)

    def check(self) -> bool:
        """
        Проверяет, не превышен ли лимит.

        Returns:
            True — можно выполнять действие
            False — лимит превышен, иди нахуй
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        # Чистим старые запросы
        self.requests = [t for t in self.requests if t > cutoff]

        if len(self.requests) >= self.max_requests:
            return False

        self.requests.append(now)
        return True

    @property
    def remaining(self) -> int:
        """Сколько запросов ещё можно сделать в этом окне."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        active = sum(1 for t in self.requests if t > cutoff)
        return max(0, self.max_requests - active)


class RateLimiter:
    """
    Ограничивает частоту действий для клиентов.

    Действия по умолчанию:
    - chat_message: 5 в секунду
    - nickname_change: 1 в 10 секунд
    - hello: 3 в минуту с одного IP
    """

    # Конфигурация лимитов по умолчанию
    DEFAULT_LIMITS = {
        'chat_message':    RateLimit(max_requests=5,  window_seconds=1.0),   # 5 msg/sec
        'nickname_change': RateLimit(max_requests=1,  window_seconds=10.0),  # 1 per 10 sec
        'hello':           RateLimit(max_requests=3,  window_seconds=60.0),  # 3 per minute
        'ping':            RateLimit(max_requests=1,  window_seconds=30.0),  # 1 per 30 sec
    }

    def __init__(self, custom_limits: Dict[str, RateLimit] | None = None):
        """
        Args:
            custom_limits: переопределение лимитов, например
                          {'chat_message': RateLimit(max_requests=10, window_seconds=1.0)}
        """
        self._limits: Dict[str, Dict[str, RateLimit]] = defaultdict(dict)
        self._config = {**self.DEFAULT_LIMITS, **(custom_limits or {})}

    def check(self, client_id: str, action: str) -> bool:
        """
        Проверяет, разрешено ли действие.

        Args:
            client_id: ID клиента (или IP для неавторизованных)
            action: тип действия ('chat_message', 'nickname_change', ...)

        Returns:
            True — разрешено, False — превышен лимит
        """
        if action not in self._config:
            return True  # Неизвестное действие — пропускаем

        if client_id not in self._limits[action]:
            template = self._config[action]
            self._limits[action][client_id] = RateLimit(
                max_requests=template.max_requests,
                window_seconds=template.window_seconds
            )

        return self._limits[action][client_id].check()

    def remaining(self, client_id: str, action: str) -> int:
        """Сколько запросов осталось у клиента для этого действия."""
        if action not in self._config:
            return 999  # Безлимит

        if client_id not in self._limits[action]:
            return self._config[action].max_requests

        return self._limits[action][client_id].remaining

    def reset(self, client_id: str) -> None:
        """Сбрасывает все лимиты для клиента (при отключении)."""
        for action_limits in self._limits.values():
            action_limits.pop(client_id, None)
