"""Cryptographic session management using ECDH + Fernet."""

import base64
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet


# Константы, чтобы не магические числа по коду
EC_CURVE = ec.SECP384R1()
HKDF_INFO = b'group-chat-handshake'
HKDF_LENGTH = 32


class SecureSession:
    """
    Сессия с end-to-end шифрованием (в реальности — client-to-server).

    Использует ECDH для согласования ключа, затем Fernet (AES-128-CBC + HMAC)
    для симметричного шифрования сообщений.

    Важно: сервер расшифровывает и заново шифрует сообщения для каждого получателя,
    поэтому НЕ является end-to-end в классическом понимании. Если нужно E2E —
    надо реализовывать Double Ratchet или хотя бы обмен ключами между клиентами.
    """

    def __init__(self):
        self._private_key = ec.generate_private_key(EC_CURVE)
        self._public_key = self._private_key.public_key()
        self.public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._fernet: Optional[Fernet] = None
        self.peer_id: Optional[str] = None
        self.peer_nickname: Optional[str] = None

    def derive_shared_key(self, peer_public_bytes: bytes) -> None:
        """
        Вычисляет общий симметричный ключ из публичного ключа пира.

        Вызывается один раз при handshake. После вызова можно шифровать/расшифровывать.
        """
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = self._private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_LENGTH,
            salt=None,
            info=HKDF_INFO,
        ).derive(shared_secret)

        # Fernet требует base64-urlsafe ключ длиной 32 байта
        self._fernet = Fernet(base64.urlsafe_b64encode(derived_key))

    def encrypt(self, plaintext: str) -> bytes:
        """Шифрует строку. Должен быть вызван derive_shared_key() перед этим."""
        if not self.ready:
            raise RuntimeError("Session not ready: call derive_shared_key() first")
        return self._fernet.encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        """Расшифровывает в строку. Должен быть вызван derive_shared_key() перед этим."""
        if not self.ready:
            raise RuntimeError("Session not ready: call derive_shared_key() first")
        return self._fernet.decrypt(ciphertext).decode('utf-8')

    @property
    def ready(self) -> bool:
        """Готова ли сессия к шифрованию/расшифрованию."""
        return self._fernet is not None

    def reset(self) -> None:
        """
        Сбрасывает сессию для повторного handshake.
        Полезно при переподключении (когда-нибудь, когда доделаем реконнект).
        """
        self._fernet = None
        self.peer_id = None
        self.peer_nickname = None
