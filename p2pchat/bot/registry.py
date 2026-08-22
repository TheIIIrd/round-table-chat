"""Разбор и выполнение команд бота.

Бот — единственный участник, который обрабатывает чужой ввод автоматически,
поэтому здесь всё построено вокруг недоверия к тексту:

* команда обязана начинаться с префикса и совпасть с якорным регулярным
  выражением целиком — никакого поиска подстроки;
* длина строки ограничена до разбора;
* на отправителя действует token bucket, иначе один участник займёт бота
  целиком и через него утопит меш;
* у обработчика есть таймаут;
* ответ обрезается до разумной длины.

Обработчики не получают ни файловой системы, ни сети — только распарсенные
аргументы и ник отправителя.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

PREFIX = "!"
MAX_INPUT_LEN = 200
MAX_REPLY_LEN = 500
HANDLER_TIMEOUT = 2.0

RATE_CAPACITY = 5.0  # столько команд подряд
RATE_REFILL_PER_SEC = 0.5  # и по одной каждые две секунды


@dataclass(frozen=True)
class Context:
    """Всё, что обработчик знает об отправителе. Никаких прав, только факты."""

    nick: str
    public: bytes


Handler = Callable[..., Awaitable[str] | str]


@dataclass
class Command:
    """Одна команда бота: имя, разбор аргументов, обработчик и строка справки."""

    name: str
    pattern: re.Pattern
    handler: Handler
    summary: str


@dataclass
class TokenBucket:
    capacity: float = RATE_CAPACITY
    refill: float = RATE_REFILL_PER_SEC
    tokens: float = RATE_CAPACITY
    updated: float = field(default_factory=time.monotonic)

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Registry:
    """Набор команд плюс защита от злоупотреблений."""

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}
        self._aliases: dict[str, str] = {}
        self._buckets: dict[bytes, TokenBucket] = {}

    def command(
        self,
        name: str,
        pattern: str = r"",
        summary: str = "",
        aliases: tuple[str, ...] = (),
    ):
        """Регистрирует обработчик. ``pattern`` якорится целиком.

        Каноническое имя английское — только оно попадает в подсказки. Русские
        синонимы работают молча: тому, кто пишет «!бросок», незачем объяснять,
        что команда «на самом деле» называется roll.
        """

        def decorate(handler: Handler) -> Handler:
            compiled = re.compile(rf"^{pattern}$" if pattern else r"^$")
            self._commands[name] = Command(
                name=name, pattern=compiled, handler=handler, summary=summary
            )
            for alias in aliases:
                self._aliases[alias] = name
            return handler

        return decorate

    def resolve(self, name: str) -> str | None:
        lowered = name.lower()
        if lowered in self._commands:
            return lowered
        return self._aliases.get(lowered)

    @property
    def names(self) -> list[str]:
        return sorted(self._commands)

    def help_lines(self) -> list[str]:
        return [
            f"{PREFIX}{cmd.name} — {cmd.summary}"
            for cmd in self._commands.values()
            if cmd.summary
        ]

    async def dispatch(self, ctx: Context, text: str) -> str | None:
        """Возвращает ответ бота или ``None``, если реагировать не нужно."""
        if len(text) > MAX_INPUT_LEN or not text.startswith(PREFIX):
            return None

        name, _, argument = text[len(PREFIX) :].strip().partition(" ")
        resolved = self.resolve(name)
        command = self._commands.get(resolved) if resolved else None
        if command is None:
            return None

        bucket = self._buckets.setdefault(ctx.public, TokenBucket())
        if not bucket.take():
            return None  # молча игнорируем: ответ на флуд — тоже флуд

        match = command.pattern.match(argument.strip())
        if match is None:
            return f"{ctx.nick}: не понял аргументы. {PREFIX}help покажет формат."

        try:
            result = command.handler(ctx, *match.groups())
            if asyncio.iscoroutine(result):
                result = await asyncio.wait_for(result, HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            return f"{ctx.nick}: команда выполнялась слишком долго и была прервана."
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # Обработчик команд — чужой код, исполняемый по вводу из сети.
            # Любое его исключение должно остаться одной строкой в чате,
            # а не уронить бота вместе с текущей партией.
            return f"{ctx.nick}: команда не выполнилась ({type(exc).__name__})."

        return str(result)[:MAX_REPLY_LEN] if result else None
