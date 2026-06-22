"""
Chat server: accepts connections, relays messages.
Звезда: все сообщения идут через сервер.

Режимы:
- Обычный: сервер расшифровывает и ретранслирует
- E2E: сервер пересылает зашифрованные блобы (peer_payloads)
  и расшифровывает свою копию (server_payload)
"""

import asyncio
import base64
import ssl
import uuid
from pathlib import Path
from typing import Dict, Optional

from server.peer import PeerConnection
from server.rate_limiter import RateLimiter
from core.protocol import read_message, send_message, MessageProtection
from core.auth import AuthManager
from core.tls import create_server_ssl_context, DEFAULT_CERT_DIR
from core.e2e import E2EManager
from utils.logging_config import get_logger
from utils.security import sanitize_message, get_nickname_error

logger = get_logger(__name__)


class ChatServer:
    """
    Сервер-ретранслятор для группового чата.

    Поддерживает:
    - TCP или TLS транспорт
    - Аутентификацию (challenge-response)
    - E2E шифрование (сервер не читает сообщения пиров)
    - Replay protection (nonce)
    - Rate limiting
    """

    def __init__(
        self,
        host: str,
        port: int,
        password: Optional[str] = None,
        use_tls: bool = False,
        cert_dir: Optional[Path] = None,
        enable_e2e: bool = False
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cert_dir = cert_dir or DEFAULT_CERT_DIR
        self.enable_e2e = enable_e2e

        self.clients: Dict[str, PeerConnection] = {}
        self._lock = asyncio.Lock()
        self._server = None

        # Сигнал что сервер готов принимать подключения
        self._ready_event = asyncio.Event()

        self._rate_limiter = RateLimiter()
        self._auth = AuthManager(password)
        self._nonce_checker = MessageProtection()
        self._ssl_context: Optional[ssl.SSLContext] = None

        # E2E менеджер сервера
        self._e2e_manager = E2EManager() if enable_e2e else None

        # Кеш E2E публичных ключей клиентов: client_id -> public_bytes
        self._e2e_public_keys: Dict[str, bytes] = {}

    async def start(self) -> None:
        """Запускает сервер."""
        if self.use_tls:
            self._ssl_context, cert_path, key_path = create_server_ssl_context(
                self.cert_dir, auto_generate=True
            )
            logger.info("TLS enabled: cert=%s", cert_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            ssl=self._ssl_context
        )

        tls_status = "TLS" if self.use_tls else "plain TCP"
        auth_status = "enabled" if self._auth.enabled else "disabled"
        e2e_status = "enabled" if self.enable_e2e else "disabled"
        logger.info("Server listening on %s:%d (%s, auth: %s, e2e: %s)",
                    self.host, self.port, tls_status, auth_status, e2e_status)

        self._ready_event.set()

        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Останавливает сервер."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        async with self._lock:
            for client in list(self.clients.values()):
                await client.close()
            self.clients.clear()

        self._ready_event.clear()
        logger.info("Server stopped")

    @property
    def is_ready(self) -> bool:
        """Готов ли сервер принимать подключения."""
        return self._ready_event.is_set()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Обрабатывает новое подключение."""
        peer = PeerConnection(reader, writer)

        addr = peer.addr[0] if peer.addr else "unknown"
        if not self._rate_limiter.check(addr, 'hello'):
            logger.warning("Rate limit exceeded for %s (hello)", addr)
            try:
                await send_message(writer, {
                    "type": "error",
                    "code": "rate_limit",
                    "text": "Too many connection attempts. Wait a bit."
                })
            except Exception:
                pass
            await peer.close()
            return

        logger.info("New connection from %s", peer.addr)

        try:
            if not await self._do_handshake(peer):
                return

            await self._register_client(peer)
            await self._message_loop(peer)

        except asyncio.CancelledError:
            logger.debug("Client handler cancelled: %s", peer)

        except Exception as e:
            logger.error("Error handling client %s: %s", peer, e)

        finally:
            if peer.client_id:
                self._rate_limiter.reset(peer.client_id)
            await self._disconnect_client(peer)

    async def _do_handshake(self, peer: PeerConnection) -> bool:
        """Handshake с опциональным E2E."""
        try:
            msg = await read_message(peer.reader)

        except Exception as e:
            logger.warning("Handshake failed for %s: %s", peer.addr, e)
            return False

        if msg.get("type") != "hello":
            logger.warning("Bad handshake from %s: expected 'hello', got '%s'",
                        peer.addr, msg.get("type"))
            try:
                await send_message(peer.writer, {
                    "type": "error",
                    "code": "bad_handshake",
                    "text": "Expected 'hello' message"
                })
            except Exception:
                pass
            return False

        nickname = msg.get("nickname", "Anonymous")
        error = get_nickname_error(nickname)
        if error:
            logger.warning("Invalid nickname from %s: %s", peer.addr, error)
            try:
                await send_message(peer.writer, {
                    "type": "error",
                    "code": "invalid_nickname",
                    "text": error
                })
            except Exception:
                pass
            return False

        # Проверяем уникальность ника
        async with self._lock:
            for client in self.clients.values():
                if client.nickname == nickname:
                    logger.warning("Duplicate nickname from %s: '%s' already taken",
                                peer.addr, nickname)
                    try:
                        await send_message(peer.writer, {
                            "type": "error",
                            "code": "nickname_taken",
                            "text": f"Nickname '{nickname}' is already taken. "
                                    f"Choose another one or use /nick later."
                        })
                    except Exception:
                        pass
                    return False

        # Аутентификация
        if self._auth.enabled:
            if not await self._do_auth(peer):
                return False

        # Ключи для client-server шифрования
        client_id = str(uuid.uuid4())

        try:
            client_pubkey = base64.b64decode(msg["public_key"])
            peer.session.derive_shared_key(client_pubkey)
        except Exception as e:
            logger.error("Key derivation failed for %s: %s", peer, e)
            return False

        peer.client_id = client_id
        peer.nickname = nickname

        # E2E: получаем публичный ключ клиента
        e2e_enabled = self.enable_e2e and "e2e_public_key" in msg
        if e2e_enabled:
            try:
                e2e_pubkey = base64.b64decode(msg["e2e_public_key"])
                self._e2e_public_keys[client_id] = e2e_pubkey

                # Создаём E2E-сессию сервера с этим клиентом
                self._e2e_manager.add_peer(client_id, e2e_pubkey)

                logger.debug("E2E session established with %s", peer)
            except Exception as e:
                logger.error("Failed to setup E2E for %s: %s", peer, e)
                e2e_enabled = False

        # Формируем welcome
        welcome_msg = {
            "type": "welcome",
            "your_id": client_id,
            "public_key": base64.b64encode(peer.session.public_bytes).decode('ascii'),
            "online_users": [
                {"id": cid, "nickname": c.nickname}
                for cid, c in self.clients.items()
            ],
            "auth_enabled": self._auth.enabled,
            "tls_enabled": self.use_tls,
            "e2e_enabled": e2e_enabled,
        }

        # E2E: добавляем ключ сервера и ключи всех участников
        if e2e_enabled:
            welcome_msg["e2e_server_public_key"] = base64.b64encode(
                self._e2e_manager.public_bytes
            ).decode('ascii')

            # Отправляем новому клиенту ключи всех существующих
            welcome_msg["e2e_peer_keys"] = {
                cid: base64.b64encode(pk).decode('ascii')
                for cid, pk in self._e2e_public_keys.items()
                if cid != client_id
            }

        try:
            await send_message(peer.writer, welcome_msg)
        except Exception as e:
            logger.error("Failed to send welcome to %s: %s", peer, e)
            return False

        # E2E: рассылаем ключ нового клиента всем существующим
        if e2e_enabled:
            await self._broadcast_e2e_key(client_id, nickname)

        logger.info("Handshake complete: %s (nick=%s, e2e=%s)",
                    peer, nickname, e2e_enabled)
        return True

    async def _do_auth(self, peer: PeerConnection) -> bool:
        """Проводит аутентификацию challenge-response."""
        challenge = self._auth.create_challenge()

        try:
            await send_message(peer.writer, {
                "type": "challenge",
                "challenge": base64.b64encode(challenge).decode('ascii')
            })

            auth_msg = await read_message(peer.reader)

            if auth_msg.get("type") != "challenge_response":
                await send_message(peer.writer, {
                    "type": "error",
                    "code": "auth_required",
                    "text": "Authentication required"
                })
                return False

            response = base64.b64decode(auth_msg.get("response", ""))

            if not self._auth.verify_response(challenge, response):
                await send_message(peer.writer, {
                    "type": "error",
                    "code": "auth_failed",
                    "text": "Invalid password"
                })
                return False

            logger.debug("Auth passed for %s", peer.addr)
            return True

        except Exception as e:
            logger.error("Auth error for %s: %s", peer.addr, e)
            return False

    async def _broadcast_e2e_key(self, new_client_id: str, new_nickname: str) -> None:
        """Рассылает E2E-ключ нового клиента всем существующим."""
        new_pubkey = self._e2e_public_keys.get(new_client_id)
        if not new_pubkey:
            return

        async with self._lock:
            for client_id, client in self.clients.items():
                if client_id == new_client_id:
                    continue
                try:
                    await send_message(client.writer, {
                        "type": "e2e_peer_joined",
                        "peer_id": new_client_id,
                        "peer_nickname": new_nickname,
                        "peer_public_key": base64.b64encode(new_pubkey).decode('ascii'),
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    })
                except Exception:
                    logger.warning("Failed to send E2E key to %s", client)

    async def _register_client(self, peer: PeerConnection) -> None:
        """Регистрирует клиента."""
        async with self._lock:
            self.clients[peer.client_id] = peer

        await self._broadcast_system(f"{peer.nickname} joined the chat", exclude=peer.client_id)
        await self._broadcast_user_list()

        logger.info("%s registered, total clients: %d", peer, len(self.clients))

    async def _message_loop(self, peer: PeerConnection) -> None:
        """Основной цикл приёма сообщений."""
        while True:
            try:
                msg = await read_message(peer.reader)
            except Exception as e:
                logger.debug("Client %s disconnected: %s", peer, e)
                break

            # Replay protection
            nonce_b64 = msg.get("nonce")
            if nonce_b64:
                try:
                    nonce = base64.b64decode(nonce_b64)
                    if not self._nonce_checker.check_nonce(nonce):
                        logger.warning("Invalid/replay nonce from %s", peer.nickname)
                        continue
                except Exception as e:
                    logger.warning("Bad nonce from %s: %s", peer.nickname, e)
                    continue

            msg_type = msg.get("type")

            if msg_type == "chat":
                await self._handle_chat(peer, msg)

            elif msg_type == "nickname_change":
                await self._handle_nickname_change(peer, msg)

            elif msg_type == "ping":
                if not self._rate_limiter.check(peer.client_id, 'ping'):
                    continue
                try:
                    await send_message(peer.writer, {
                        "type": "pong",
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    })
                except Exception:
                    break
            else:
                logger.warning("Unknown message type from %s: %s", peer, msg_type)

    async def _handle_chat(self, peer: PeerConnection, msg: dict) -> None:
        """Обрабатывает chat-сообщение."""
        if not self._rate_limiter.check(peer.client_id, 'chat_message'):
            logger.warning("Rate limit exceeded for %s (chat)", peer.nickname)
            return

        # E2E режим: пересылаем peer_payloads + расшифровываем server_payload
        if self.enable_e2e and "peer_payloads" in msg:
            await self._handle_e2e_chat(peer, msg)
            return

        # Обычный режим: расшифровываем и ретранслируем
        try:
            ciphertext = base64.b64decode(msg["payload"])
            plaintext = peer.session.decrypt(ciphertext)
        except Exception as e:
            logger.warning("Failed to decrypt message from %s: %s", peer, e)
            return

        is_valid, result = sanitize_message(plaintext)
        if not is_valid:
            return

        logger.debug("Chat from %s: %s", peer.nickname, result[:50])
        await self._broadcast_chat(peer, result)

    async def _handle_e2e_chat(self, peer: PeerConnection, msg: dict) -> None:
        """
        Обрабатывает E2E chat-сообщение.

        Сервер:
        1. Расшифровывает server_payload (чтобы показать в своём UI)
        2. Рассылает peer_payloads соответствующим клиентам
        """
        # Расшифровываем свою копию
        server_plaintext = None
        server_payload_b64 = msg.get("server_payload")
        if server_payload_b64:
            try:
                server_ciphertext = base64.b64decode(server_payload_b64)
                server_plaintext = self._e2e_manager.decrypt_from_peer(
                    peer.client_id, server_ciphertext
                )

                # Санитизируем
                is_valid, result = sanitize_message(server_plaintext)
                if is_valid:
                    server_plaintext = result
                    logger.debug("E2E chat from %s (server copy): %s",
                                peer.nickname, server_plaintext[:50])
                else:
                    server_plaintext = None
            except Exception as e:
                logger.warning("Failed to decrypt server_payload from %s: %s", peer, e)

        # Рассылаем peer_payloads
        peer_payloads = msg.get("peer_payloads", {})

        async with self._lock:
            dead_clients = []

            for client_id, client in self.clients.items():
                if client_id == peer.client_id:
                    continue

                # Для каждого клиента ищем его персональный payload
                client_payload_b64 = peer_payloads.get(client_id)

                if client_payload_b64:
                    # E2E: пересылаем готовый шифроблоб
                    forward_msg = {
                        "type": "chat",
                        "sender_id": peer.client_id,
                        "nickname": peer.nickname,
                        "payload": client_payload_b64,
                        "e2e": True,
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    }

                else:
                    # Нет E2E- payload для этого клиента — шифруем через server_session
                    if server_plaintext:
                        try:
                            ciphertext = client.session.encrypt(server_plaintext)
                            forward_msg = {
                                "type": "chat",
                                "sender_id": peer.client_id,
                                "nickname": peer.nickname,
                                "payload": base64.b64encode(ciphertext).decode('ascii'),
                                "e2e": False,
                                "nonce": base64.b64encode(
                                    self._nonce_checker.create_nonce()
                                ).decode('ascii')
                            }
                        except Exception:
                            continue
                    else:
                        continue

                try:
                    await send_message(client.writer, forward_msg)

                except Exception:
                    logger.warning("Failed to send to %s, marking as dead", client)
                    dead_clients.append(client_id)

            for client_id in dead_clients:
                await self._remove_client(client_id)

    async def _handle_nickname_change(self, peer: PeerConnection, msg: dict) -> None:
        """Обрабатывает смену ника."""
        if not self._rate_limiter.check(peer.client_id, 'nickname_change'):
            return

        new_nick = msg.get("new_nickname", "").strip()
        old_nick = peer.nickname

        error = get_nickname_error(new_nick)
        if error:
            try:
                await send_message(peer.writer, {
                    "type": "error",
                    "code": "invalid_nickname",
                    "text": error
                })
            except Exception:
                pass
            return

        async with self._lock:
            for client in self.clients.values():
                if client.client_id != peer.client_id and client.nickname == new_nick:
                    try:
                        await send_message(peer.writer, {
                            "type": "error",
                            "code": "nickname_taken",
                            "text": f"Nickname '{new_nick}' is already taken"
                        })
                    except Exception:
                        pass
                    return

        peer.nickname = new_nick
        logger.info("Nickname change: %s -> %s", old_nick, new_nick)
        await self._broadcast_system(f"{old_nick} is now {new_nick}", exclude=peer.client_id)
        await self._broadcast_user_list()

    async def _broadcast_chat(self, sender: PeerConnection, plaintext: str) -> None:
        """Обычная рассылка (без E2E)."""
        async with self._lock:
            dead_clients = []

            for client_id, client in self.clients.items():
                if client_id == sender.client_id:
                    continue

                try:
                    ciphertext = client.session.encrypt(plaintext)
                    await send_message(client.writer, {
                        "type": "chat",
                        "sender_id": sender.client_id,
                        "nickname": sender.nickname,
                        "payload": base64.b64encode(ciphertext).decode('ascii'),
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    })

                except Exception:
                    logger.warning("Failed to send to %s, marking as dead", client)
                    dead_clients.append(client_id)

            for client_id in dead_clients:
                await self._remove_client(client_id)

    async def _broadcast_system(self, text: str, exclude: Optional[str] = None) -> None:
        """Рассылает системное сообщение."""
        async with self._lock:
            for client_id, client in self.clients.items():
                if client_id == exclude:
                    continue
                try:
                    await send_message(client.writer, {
                        "type": "system",
                        "text": text,
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    })
                except Exception:
                    logger.warning("Failed to send system message to %s", client)

    async def _broadcast_user_list(self) -> None:
        """Рассылает список пользователей."""
        async with self._lock:
            user_list = [
                {"id": cid, "nickname": c.nickname}
                for cid, c in self.clients.items()
            ]

            for client in self.clients.values():
                try:
                    await send_message(client.writer, {
                        "type": "user_list",
                        "users": user_list,
                        "nonce": base64.b64encode(
                            self._nonce_checker.create_nonce()
                        ).decode('ascii')
                    })
                except Exception:
                    logger.warning("Failed to send user list to %s", client)

    async def _disconnect_client(self, peer: PeerConnection) -> None:
        """Отключает клиента."""
        if peer.client_id:
            await self._remove_client(peer.client_id)
            await self._broadcast_system(f"{peer.nickname} left the chat")
            await self._broadcast_user_list()

        await peer.close()

    async def _remove_client(self, client_id: str) -> None:
        """Удаляет клиента из списка."""
        async with self._lock:
            client = self.clients.pop(client_id, None)
            if client:
                logger.info("%s removed, total clients: %d", client, len(self.clients))

        # Удаляем E2E-сессию и ключ
        if self.enable_e2e:
            self._e2e_manager.remove_peer(client_id)
            self._e2e_public_keys.pop(client_id, None)
