"""
Wire protocol: length-prefixed JSON messages over TCP.

Формат: [4 bytes length (big-endian)][JSON payload (UTF-8)]
Максимальный размер сообщения: PROTOCOL_MAX_MESSAGE_SIZE байт.

Replay protection: каждое сообщение содержит nonce.
Nonce = timestamp(8) + random(8) + counter(8) = 24 байта.
"""

import json
import asyncio
import time
import os
from typing import Any, Dict, Optional


PROTOCOL_MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 МБ
PROTOCOL_LENGTH_PREFIX_SIZE = 4

NONCE_MAX_AGE_SECONDS = 60
MAX_SEEN_NONCES = 10000


class ProtocolError(Exception):
    """Ошибка протокола: невалидное сообщение, превышен размер и т.д."""
    pass


class MessageProtection:
    """
    Защита от replay-атак через nonce.
    """

    def __init__(self, max_age_seconds: int = NONCE_MAX_AGE_SECONDS):
        self._counter = 0
        self._seen_nonces: set[bytes] = set()
        self._max_age = max_age_seconds

    def create_nonce(self) -> bytes:
        """Создаёт уникальный nonce."""
        ts = int(time.time() * 1000).to_bytes(8, 'big')
        rand = os.urandom(8)
        self._counter += 1
        ctr = (self._counter % (2**64)).to_bytes(8, 'big')
        return ts + rand + ctr

    def check_nonce(self, nonce: bytes) -> bool:
        """Проверяет валидность nonce."""
        if len(nonce) != 24:
            return False

        if nonce in self._seen_nonces:
            return False

        ts = int.from_bytes(nonce[:8], 'big') / 1000.0
        now = time.time()
        age = now - ts

        if age > self._max_age:
            return False

        if age < -5.0:
            return False

        self._seen_nonces.add(nonce)

        if len(self._seen_nonces) > MAX_SEEN_NONCES:
            to_remove = list(self._seen_nonces)[:MAX_SEEN_NONCES // 2]
            for n in to_remove:
                self._seen_nonces.discard(n)

        return True

    def reset(self) -> None:
        """Сбрасывает кеш nonce и счётчик."""
        self._counter = 0
        self._seen_nonces.clear()


async def read_message(reader: asyncio.StreamReader) -> Dict[str, Any]:
    """Читает одно сообщение из стрима."""
    try:
        length_bytes = await reader.readexactly(PROTOCOL_LENGTH_PREFIX_SIZE)
    except asyncio.IncompleteReadError:
        raise

    length = int.from_bytes(length_bytes, 'big')

    if length < 0 or length > PROTOCOL_MAX_MESSAGE_SIZE:
        raise ProtocolError(
            f"Invalid message length: {length}. "
            f"Must be 0..{PROTOCOL_MAX_MESSAGE_SIZE}"
        )

    try:
        data = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise

    try:
        return json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"Failed to decode message: {e}")


async def send_message(writer: asyncio.StreamWriter, message: Dict[str, Any]) -> None:
    """Отправляет одно сообщение в стрим."""
    data = json.dumps(message, ensure_ascii=False).encode('utf-8')

    if len(data) > PROTOCOL_MAX_MESSAGE_SIZE:
        raise ProtocolError(
            f"Message too large: {len(data)} bytes. "
            f"Max: {PROTOCOL_MAX_MESSAGE_SIZE}"
        )

    writer.write(len(data).to_bytes(PROTOCOL_LENGTH_PREFIX_SIZE, 'big') + data)
    await writer.drain()
