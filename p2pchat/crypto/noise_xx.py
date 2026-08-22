"""Паттерн Noise_XX: взаимная аутентификация со скрытием идентичности.

    -> e
    <- e, ee, s, es
    -> s, se

Статический ключ каждой стороны передаётся уже зашифрованным, поэтому
пассивный наблюдатель не видит, кто с кем разговаривает. Стойкость к
активному MITM обеспечивается не самим паттерном, а последующей сверкой
SAS-кода: XX подтверждает лишь, что у собеседника есть приватный ключ к
предъявленному публичному, но не то, что этот публичный ключ — тот самый.
"""

from __future__ import annotations

from collections.abc import Callable

from . import primitives as p
from .noise import PROTOCOL_NAME, CipherState, NoiseError, SymmetricState

MESSAGE_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("e",),
    ("e", "ee", "s", "es"),
    ("s", "se"),
)


class HandshakeState:
    """Одна сторона хендшейка XX.

    Стороны вызывают ``write_message`` и ``read_message`` строго по очереди;
    инициатор пишет первым. Когда ``is_complete`` становится истиной, ключи
    транспорта доступны через ``split``.
    """

    def __init__(
        self,
        *,
        initiator: bool,
        static: p.KeyPair,
        prologue: bytes = b"",
        ephemeral_factory: Callable[[], p.KeyPair] = p.KeyPair.generate,
    ) -> None:
        self.initiator = initiator
        self.s = static
        self.e: p.KeyPair | None = None
        self.rs: bytes | None = None
        self.re: bytes | None = None
        self._ephemeral_factory = ephemeral_factory
        self._patterns = list(MESSAGE_PATTERNS)
        self._turn_to_write = initiator

        self.symmetric = SymmetricState(PROTOCOL_NAME)
        self.symmetric.mix_hash(prologue)

    @property
    def is_complete(self) -> bool:
        return not self._patterns

    @property
    def handshake_hash(self) -> bytes:
        """Значение ``h``. После завершения хендшейка одинаково у обеих сторон
        и служит входом для SAS-кода."""
        return self.symmetric.h

    @property
    def chaining_key(self) -> bytes:
        """Значение ``ck`` на момент завершения хендшейка.

        Сессия продолжает эту цепочку при ротации ключей, поэтому каждая
        ротация криптографически связана со всей историей соединения.
        """
        return self.symmetric.ck

    @property
    def remote_static(self) -> bytes:
        if self.rs is None:
            raise NoiseError("статический ключ пира ещё не получен")
        return self.rs

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.is_complete:
            raise NoiseError("хендшейк уже завершён")
        if not self._turn_to_write:
            raise NoiseError("сейчас очередь читать, а не писать")

        buffer = bytearray()
        for token in self._patterns.pop(0):
            if token == "e":
                self.e = self._ephemeral_factory()
                buffer += self.e.public
                self.symmetric.mix_hash(self.e.public)
            elif token == "s":
                buffer += self.symmetric.encrypt_and_hash(self.s.public)
            else:
                self.symmetric.mix_key(self._dh_for(token))

        buffer += self.symmetric.encrypt_and_hash(payload)
        self._turn_to_write = False
        return bytes(buffer)

    def read_message(self, message: bytes) -> bytes:
        if self.is_complete:
            raise NoiseError("хендшейк уже завершён")
        if self._turn_to_write:
            raise NoiseError("сейчас очередь писать, а не читать")

        view = memoryview(message)
        offset = 0
        for token in self._patterns.pop(0):
            if token == "e":
                offset = self._take(view, offset, p.DHLEN, "эфемерный ключ")
                self.re = bytes(view[offset - p.DHLEN : offset])
                self.symmetric.mix_hash(self.re)
            elif token == "s":
                size = p.DHLEN + (p.TAGLEN if self.symmetric.cipher_state.has_key() else 0)
                offset = self._take(view, offset, size, "статический ключ")
                self.rs = self.symmetric.decrypt_and_hash(bytes(view[offset - size : offset]))
            else:
                self.symmetric.mix_key(self._dh_for(token))

        payload = self.symmetric.decrypt_and_hash(bytes(view[offset:]))
        self._turn_to_write = True
        return payload

    def split(self) -> tuple[CipherState, CipherState]:
        """Возвращает ``(на отправку, на приём)`` для этой стороны."""
        if not self.is_complete:
            raise NoiseError("хендшейк не завершён")
        c1, c2 = self.symmetric.split()
        return (c1, c2) if self.initiator else (c2, c1)

    def _dh_for(self, token: str) -> bytes:
        """Выбирает пару ключей для DH-токена.

        Раньше здесь стояли ``assert``, но они исчезают при запуске с ``-O``,
        а в криптокоде проверка, которую можно отключить флагом, — это
        отсутствующая проверка.
        """
        if token == "ee":
            return p.dh(self._my_e(token), self._their_e(token))
        if token == "es":
            if self.initiator:
                return p.dh(self._my_e(token), self._their_s(token))
            return p.dh(self.s, self._their_e(token))
        if token == "se":
            if self.initiator:
                return p.dh(self.s, self._their_e(token))
            return p.dh(self._my_e(token), self._their_s(token))
        raise NoiseError(f"неизвестный токен паттерна: {token}")

    def _my_e(self, token: str) -> p.KeyPair:
        if self.e is None:
            raise NoiseError(f"токен {token}: локальный эфемерный ключ ещё не создан")
        return self.e

    def _their_e(self, token: str) -> bytes:
        if self.re is None:
            raise NoiseError(f"токен {token}: эфемерный ключ пира ещё не получен")
        return self.re

    def _their_s(self, token: str) -> bytes:
        if self.rs is None:
            raise NoiseError(f"токен {token}: статический ключ пира ещё не получен")
        return self.rs

    @staticmethod
    def _take(view: memoryview, offset: int, size: int, what: str) -> int:
        if len(view) - offset < size:
            raise NoiseError(f"сообщение обрывается там, где ожидался {what}")
        return offset + size
