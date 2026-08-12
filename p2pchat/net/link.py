"""Абстракция канала передачи кадров.

Криптослой не должен ничего знать о сети. Всё, что ему нужно, — уметь
отправить и получить кадр. Благодаря этому сессия целиком тестируется на
``MemoryLink`` без единого сокета, а добавление UDP на седьмом этапе не
потребует правок в ``session.py``.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod


class LinkClosed(Exception):
    """Канал закрыт — своей стороной, пиром или из-за ошибки сети."""


class Link(ABC):
    """Двунаправленный упорядоченный канал кадров."""

    @abstractmethod
    async def send_frame(self, payload: bytes) -> None: ...

    @abstractmethod
    async def recv_frame(self) -> bytes: ...

    @abstractmethod
    async def close(self) -> None: ...

    @property
    def description(self) -> str:
        return self.__class__.__name__

    async def __aenter__(self) -> "Link":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()


class MemoryLink(Link):
    """Пара связанных каналов в памяти. Только для тестов и демонстраций."""

    def __init__(self, inbox: asyncio.Queue, outbox: asyncio.Queue) -> None:
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False

    @classmethod
    def pair(cls) -> tuple["MemoryLink", "MemoryLink"]:
        a_to_b: asyncio.Queue = asyncio.Queue()
        b_to_a: asyncio.Queue = asyncio.Queue()
        return cls(b_to_a, a_to_b), cls(a_to_b, b_to_a)

    async def send_frame(self, payload: bytes) -> None:
        if self._closed:
            raise LinkClosed("канал закрыт")
        await self._outbox.put(payload)

    async def recv_frame(self) -> bytes:
        if self._closed:
            raise LinkClosed("канал закрыт")
        frame = await self._inbox.get()
        if frame is None:
            raise LinkClosed("пир закрыл канал")
        return frame

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._outbox.put(None)
