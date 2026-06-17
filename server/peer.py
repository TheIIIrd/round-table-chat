"""Peer connection representation on the server side."""

import asyncio
from typing import Optional

from core.crypto import SecureSession
from utils.logging_config import get_logger

logger = get_logger(__name__)


class PeerConnection:
    """
    Представление подключённого клиента на сервере.

    Хранит:
    - reader/writer для сетевого обмена
    - криптографическую сессию
    - метаданные (ID, ник, адрес)
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.session = SecureSession()
        self.client_id: Optional[str] = None
        self.nickname: Optional[str] = None
        self.addr = writer.get_extra_info('peername')

    @property
    def short_id(self) -> str:
        """Возвращает первые 8 символов ID для логов."""
        return self.client_id[:8] if self.client_id else "????"

    def __repr__(self) -> str:
        return f"Peer({self.nickname or '?'}@{self.addr}, id={self.short_id})"

    async def close(self) -> None:
        """Закрывает соединение с клиентом."""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        logger.debug("Connection closed: %s", self)
