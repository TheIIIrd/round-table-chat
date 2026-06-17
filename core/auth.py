"""
Pre-shared key authentication for chat server.
Клиент должен доказать, что знает пароль, не передавая его по сети.

Протокол challenge-response:
1. Клиент: hello (nickname, public_key)
2. Сервер: challenge (32 random bytes)
3. Клиент: challenge_response (HMAC-SHA256(challenge, key))
4. Сервер: welcome или пошёл нахуй
"""

import hashlib
import hmac
import os
from typing import Optional


class AuthManager:
    """
    Управляет аутентификацией по общему паролю.

    Пароль хешируется в ключ. Ключ используется для HMAC.
    Сам пароль никогда не передаётся по сети.
    """

    CHALLENGE_LENGTH = 32  # Длина случайного вызова в байтах

    def __init__(self, password: Optional[str] = None):
        """
        Args:
            password: общий пароль чата. Если None — аутентификация отключена.
        """
        self._enabled = password is not None
        self._key: Optional[bytes] = None

        if self._enabled:
            # Хешируем пароль в ключ. SHA-256 даёт 32 байта.
            self._key = hashlib.sha256(password.encode('utf-8')).digest()

    @property
    def enabled(self) -> bool:
        """Включена ли аутентификация."""
        return self._enabled

    def create_challenge(self) -> bytes:
        """
        Генерирует случайный вызов для клиента.
        Сервер вызывает при получении hello.
        """
        return os.urandom(self.CHALLENGE_LENGTH)

    def solve_challenge(self, challenge: bytes) -> bytes:
        """
        Клиент вычисляет ответ на вызов.
        HMAC-SHA256(challenge, key).
        """
        if not self._enabled:
            raise RuntimeError("Auth is not enabled")
        return hmac.new(self._key, challenge, hashlib.sha256).digest()

    def verify_response(self, challenge: bytes, response: bytes) -> bool:
        """
        Сервер проверяет ответ клиента.
        Использует hmac.compare_digest для защиты от timing-атак.
        """
        if not self._enabled:
            return True  # Если аутентификация отключена — все проходят

        expected = hmac.new(self._key, challenge, hashlib.sha256).digest()
        return hmac.compare_digest(expected, response)
