"""
End-to-end encryption between chat clients.
Сервер не может читать сообщения, только пересылает зашифрованные блобы.

Как работает:
1. Каждый клиент при handshake передаёт свой E2E-публичный ключ
2. Сервер собирает ключи всех и рассылает новому клиенту
3. Клиент создаёт E2E-сессии со всеми остальными участниками
4. При отправке сообщения клиент шифрует его для каждого получателя отдельно
5. Сервер тупо пересылает зашифрованные блобы, не может расшифровать

Формат сообщения:
{
    "type": "chat",
    "server_payload": "base64(encrypted_for_server)",   # копия для сервера
    "peer_payloads": {                                   # копии для пиров
        "bob_id": "base64(encrypted_for_bob)",
        "charlie_id": "base64(encrypted_for_charlie)"
    },
    "nonce": "..."
}
"""

import base64
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    Encoding,
    PublicFormat,
)
from cryptography.fernet import Fernet

from utils.logging_config import get_logger

logger = get_logger(__name__)

# Отдельная кривая для E2E (можно ту же, но лучше отдельно для изоляции)
E2E_CURVE = ec.SECP384R1()
E2E_HKDF_INFO = b'e2e-chat-key-v1'


class E2ESession:
    """
    Одна E2E-сессия между двумя участниками.
    Симметричный ключ получен через ECDH.
    """

    def __init__(self, my_private_key, peer_public_bytes: bytes):
        """
        Args:
            my_private_key: мой приватный E2E-ключ
            peer_public_bytes: публичный ключ другого участника (PEM)
        """
        peer_key = load_pem_public_key(peer_public_bytes)
        shared = my_private_key.exchange(ec.ECDH(), peer_key)

        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=E2E_HKDF_INFO,
        ).derive(shared)

        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, plaintext: str) -> bytes:
        """Шифрует сообщение для этого получателя."""
        return self._fernet.encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        """Расшифровывает сообщение от этого отправителя."""
        return self._fernet.decrypt(ciphertext).decode('utf-8')


class E2EManager:
    """
    Управляет E2E-сессиями клиента.

    На клиенте:
    - Одна пара ключей (моя)
    - Одна сессия с сервером (server_session)
    - По одной сессии с каждым другим участником (peer_sessions)
    """

    def __init__(self):
        self._private_key = ec.generate_private_key(E2E_CURVE)
        self._public_key = self._private_key.public_key()

        # Публичный ключ в PEM для отправки серверу
        self.public_bytes = self._public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        # Сессия с сервером (чтобы сервер мог читать, если он доверенный)
        self._server_session: Optional[E2ESession] = None

        # Сессии с другими участниками: peer_id -> E2ESession
        self._peer_sessions: Dict[str, E2ESession] = {}

        # Кеш публичных ключей пиров: peer_id -> public_bytes
        self._peer_public_keys: Dict[str, bytes] = {}

    @property
    def server_session_ready(self) -> bool:
        """Готова ли сессия с сервером."""
        return self._server_session is not None

    def establish_server_session(self, server_public_bytes: bytes) -> None:
        """
        Создаёт сессию с сервером.
        Вызывается после получения welcome от сервера.
        """
        self._server_session = E2ESession(self._private_key, server_public_bytes)
        logger.debug("E2E server session established")

    def add_peer(self, peer_id: str, peer_public_bytes: bytes) -> None:
        """
        Добавляет другого участника.
        Вызывается при получении user_list с E2E-ключами.
        """
        if peer_id not in self._peer_sessions:
            self._peer_public_keys[peer_id] = peer_public_bytes
            self._peer_sessions[peer_id] = E2ESession(self._private_key, peer_public_bytes)
            logger.debug("E2E peer session added: %s", peer_id[:8])

    def remove_peer(self, peer_id: str) -> None:
        """Удаляет участника (при отключении)."""
        self._peer_sessions.pop(peer_id, None)
        self._peer_public_keys.pop(peer_id, None)
        logger.debug("E2E peer session removed: %s", peer_id[:8])

    def get_peer_ids(self) -> list[str]:
        """Возвращает список ID известных пиров."""
        return list(self._peer_sessions.keys())

    def encrypt_for_server(self, plaintext: str) -> bytes:
        """Шифрует сообщение для сервера."""
        if not self._server_session:
            raise RuntimeError("Server session not established")
        return self._server_session.encrypt(plaintext)

    def encrypt_for_peer(self, peer_id: str, plaintext: str) -> bytes:
        """Шифрует сообщение для конкретного получателя."""
        if peer_id not in self._peer_sessions:
            raise RuntimeError(f"No session for peer {peer_id[:8]}")
        return self._peer_sessions[peer_id].encrypt(plaintext)

    def decrypt_from_server(self, ciphertext: bytes) -> str:
        """Расшифровывает сообщение от сервера."""
        if not self._server_session:
            raise RuntimeError("Server session not established")
        return self._server_session.decrypt(ciphertext)

    def decrypt_from_peer(self, peer_id: str, ciphertext: bytes) -> str:
        """Расшифровывает сообщение от другого участника."""
        if peer_id not in self._peer_sessions:
            # Возможно, мы ещё не получили ключ этого пира
            # Пробуем создать сессию на лету, если ключ есть
            if peer_id in self._peer_public_keys:
                self._peer_sessions[peer_id] = E2ESession(
                    self._private_key, self._peer_public_keys[peer_id]
                )
            else:
                raise RuntimeError(f"No session or public key for peer {peer_id[:8]}")

        return self._peer_sessions[peer_id].decrypt(ciphertext)

    def encrypt_for_all(self, plaintext: str) -> tuple[bytes, dict[str, bytes]]:
        """
        Шифрует сообщение для сервера и всех известных пиров.

        Returns:
            (server_payload, {peer_id: peer_payload})
        """
        server_payload = self.encrypt_for_server(plaintext)

        peer_payloads = {}
        for peer_id in self._peer_sessions:
            try:
                peer_payloads[peer_id] = self.encrypt_for_peer(peer_id, plaintext)
            except Exception as e:
                logger.warning("Failed to encrypt for peer %s: %s", peer_id[:8], e)

        return server_payload, peer_payloads
