"""Core module: cryptography, protocol, authentication, TLS, E2E."""

from core.crypto import SecureSession
from core.protocol import (
    read_message,
    send_message,
    ProtocolError,
    MessageProtection,
    PROTOCOL_MAX_MESSAGE_SIZE,
    NONCE_MAX_AGE_SECONDS,
)
from core.auth import AuthManager
from core.e2e import E2EManager, E2ESession

__all__ = [
    'SecureSession',
    'read_message',
    'send_message',
    'ProtocolError',
    'MessageProtection',
    'AuthManager',
    'E2EManager',
    'E2ESession',
    'PROTOCOL_MAX_MESSAGE_SIZE',
    'NONCE_MAX_AGE_SECONDS',
]
