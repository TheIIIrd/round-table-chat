"""
Chat client: connects to server, sends/receives messages.
Поддерживает E2E шифрование.
"""

import asyncio
import base64
import ssl
from typing import Optional, TYPE_CHECKING

from core.crypto import SecureSession
from core.protocol import read_message, send_message, ProtocolError, MessageProtection
from core.auth import AuthManager
from core.tls import create_client_ssl_context
from core.e2e import E2EManager
from utils.validators import parse_peer_address
from utils.logging_config import get_logger

if TYPE_CHECKING:
    from ui.chat_ui import ChatUI
    from server.server import ChatServer

logger = get_logger(__name__)


class ChatClient:
    """
    Сетевой клиент чата с E2E поддержкой.
    """

    def __init__(
        self,
        ui: 'ChatUI',
        host: str,
        port: int,
        peer_addr: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = False,
        enable_e2e: bool = False
    ):
        self.ui = ui
        self.host = host
        self.port = port
        self.peer_addr = peer_addr
        self.password = password
        self.use_tls = use_tls
        self.enable_e2e = enable_e2e

        self.session: Optional[SecureSession] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.client_id: Optional[str] = None

        self._server_mode = False
        self._server: Optional['ChatServer'] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._auth = AuthManager(password)
        self._nonce_checker = MessageProtection()
        self._ssl_context: Optional[ssl.SSLContext] = None

        # E2E менеджер
        self._e2e_manager = E2EManager() if enable_e2e else None

        # E2E сессия с сервером установлена?
        self._e2e_ready = False

    async def start(self) -> None:
        """Запускает клиент."""
        if self.peer_addr:
            await self._connect_to_server()
        else:
            await self._start_as_server()

    async def stop(self) -> None:
        """Останавливает клиент."""
        logger.info("Stopping client...")

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass

        if self._server:
            await self._server.stop()

        self.ui.connected = False
        self.ui.status_text = "Disconnected"
        logger.info("Client stopped")

    async def _start_as_server(self) -> None:
        """Запускает встроенный сервер."""
        self._server_mode = True

        from server.server import ChatServer
        self._server = ChatServer(
            self.host, self.port,
            password=self.password,
            use_tls=self.use_tls,
            enable_e2e=self.enable_e2e
        )
        asyncio.create_task(self._server.start())

        await asyncio.sleep(0.5)

        self.peer_addr = f"127.0.0.1:{self.port}"
        await self._connect_to_server()

    async def _connect_to_server(self) -> None:
        """Подключается к серверу с E2E handshake."""
        self.session = SecureSession()

        peer_host, peer_port, error = parse_peer_address(self.peer_addr)
        if error:
            self.ui.add_system(f"Invalid address: {error}")
            return

        transport = "TLS" if self.use_tls else "TCP"
        e2e_text = "E2E" if self.enable_e2e else "no-E2E"
        self.ui.add_system(f"Connecting to {peer_host}:{peer_port} ({transport}, {e2e_text})...")

        if self.use_tls:
            self._ssl_context = create_client_ssl_context(check_hostname=False)

        try:
            self.reader, self.writer = await asyncio.open_connection(
                peer_host, peer_port, ssl=self._ssl_context
            )
        except Exception as e:
            self.ui.add_system(f"Connection failed: {e}")
            return

        try:
            # Hello с E2E-ключом
            hello_msg = {
                "type": "hello",
                "nickname": self.ui.my_nickname,
                "public_key": base64.b64encode(self.session.public_bytes).decode('ascii')
            }

            if self.enable_e2e:
                hello_msg["e2e_public_key"] = base64.b64encode(
                    self._e2e_manager.public_bytes
                ).decode('ascii')

            await send_message(self.writer, hello_msg)

            msg = await read_message(self.reader)

            if msg.get("type") == "error":
                self.ui.add_system(f"Server rejected: {msg.get('text')}")
                await self.stop()
                return

            # Аутентификация
            if msg.get("type") == "challenge":
                if not self._auth.enabled:
                    self.ui.add_system("Server requires password but none provided")
                    await self.stop()
                    return

                challenge = base64.b64decode(msg["challenge"])
                response = self._auth.solve_challenge(challenge)

                await send_message(self.writer, {
                    "type": "challenge_response",
                    "response": base64.b64encode(response).decode('ascii')
                })

                msg = await read_message(self.reader)

                if msg.get("type") == "error":
                    self.ui.add_system(f"Auth failed: {msg.get('text')}")
                    await self.stop()
                    return

            # Welcome
            if msg.get("type") != "welcome":
                raise ProtocolError(f"Expected 'welcome', got '{msg.get('type')}'")

            server_pubkey = base64.b64decode(msg["public_key"])
            self.session.derive_shared_key(server_pubkey)
            self.client_id = msg["your_id"]

            # E2E: устанавливаем сессию с сервером и пирами
            if self.enable_e2e and msg.get("e2e_enabled"):
                await self._setup_e2e(msg)

            users = [u["nickname"] for u in msg.get("online_users", [])]
            users.append(self.ui.my_nickname)
            self.ui.update_users(users)

            self.ui.connected = True

            status_parts = [f"{len(users)} user(s)"]
            if msg.get("tls_enabled"):
                status_parts.append("TLS")
            if msg.get("e2e_enabled"):
                status_parts.append("E2E")

            self.ui.add_system(f"Connected! {', '.join(status_parts)}")
            self.ui.status_text = "Connected"
            self.ui._redraw()

        except Exception as e:
            self.ui.add_system(f"Handshake failed: {e}")
            await self.stop()
            return

        self._receive_task = asyncio.create_task(self._receive_loop())

    async def _setup_e2e(self, welcome_msg: dict) -> None:
        """Настраивает E2E сессии после welcome."""
        # Сессия с сервером
        server_e2e_key = base64.b64decode(welcome_msg["e2e_server_public_key"])
        self._e2e_manager.establish_server_session(server_e2e_key)

        # Сессии с существующими пирами
        peer_keys = welcome_msg.get("e2e_peer_keys", {})
        for peer_id, peer_key_b64 in peer_keys.items():
            peer_key = base64.b64decode(peer_key_b64)
            self._e2e_manager.add_peer(peer_id, peer_key)

        self._e2e_ready = True
        logger.info("E2E ready: server + %d peers", len(peer_keys))

    async def _receive_loop(self) -> None:
        """Цикл приёма сообщений."""
        while self.reader:
            try:
                msg = await read_message(self.reader)
            except asyncio.IncompleteReadError:
                self.ui.add_system("Disconnected from server")
                break
            except ProtocolError as e:
                self.ui.add_system(f"Protocol error: {e}")
                break
            except Exception as e:
                self.ui.add_system(f"Connection error: {e}")
                break

            # Replay protection
            nonce_b64 = msg.get("nonce")
            if nonce_b64:
                try:
                    nonce = base64.b64decode(nonce_b64)
                    if not self._nonce_checker.check_nonce(nonce):
                        continue
                except Exception:
                    continue

            await self._process_message(msg)

        self.ui.connected = False
        self.ui.status_text = "Disconnected"

    async def _process_message(self, msg: dict) -> None:
        """Обрабатывает одно входящее сообщение."""
        msg_type = msg.get("type")

        if msg_type == "chat":
            await self._process_chat(msg)
        elif msg_type == "system":
            self.ui.add_system(msg["text"])
        elif msg_type == "user_list":
            users = [u["nickname"] for u in msg.get("users", [])]
            self.ui.update_users(users)
        elif msg_type == "e2e_peer_joined":
            # Новый участник с E2E-ключом
            if self.enable_e2e and self._e2e_ready:
                peer_id = msg["peer_id"]
                peer_key = base64.b64decode(msg["peer_public_key"])
                peer_nick = msg.get("peer_nickname", "???")
                self._e2e_manager.add_peer(peer_id, peer_key)
                logger.debug("E2E peer added: %s (%s)", peer_nick, peer_id[:8])
        elif msg_type == "error":
            self.ui.add_system(f"Server error: {msg.get('text', 'Unknown error')}")
        elif msg_type == "pong":
            pass
        else:
            logger.debug("Unknown message type: %s", msg_type)

    async def _process_chat(self, msg: dict) -> None:
        """Расшифровывает и отображает входящее сообщение."""
        sender_nick = msg.get("nickname", "???")
        sender_id = msg.get("sender_id", "")
        is_e2e = msg.get("e2e", False)

        try:
            if is_e2e and self.enable_e2e and self._e2e_ready:
                # E2E сообщение — расшифровываем через E2E-сессию с отправителем
                ciphertext = base64.b64decode(msg["payload"])
                try:
                    plaintext = self._e2e_manager.decrypt_from_peer(sender_id, ciphertext)
                except RuntimeError:
                    # Возможно, ещё нет сессии — пропускаем
                    logger.debug("No E2E session for %s, skipping message", sender_id[:8])
                    return
            else:
                # Обычное сообщение — расшифровываем через client-server сессию
                ciphertext = base64.b64decode(msg["payload"])
                plaintext = self.session.decrypt(ciphertext)
        except Exception as e:
            logger.warning("Failed to decrypt message from %s: %s", sender_nick, e)
            return

        if sender_nick != self.ui.my_nickname:
            self.ui.add_message(plaintext, 'peer', sender_nick)

    async def send_text(self, text: str) -> None:
        """Отправляет текстовое сообщение (или команду)."""
        from client.commands import CommandHandler

        cmd_handler = CommandHandler(self)
        is_command = await cmd_handler.handle(text)
        if is_command:
            return

        if not self.writer or not self.session or not self.session.ready:
            self.ui.add_system("Not connected to server")
            return

        if not text.strip():
            return

        try:
            if self.enable_e2e and self._e2e_ready:
                # E2E режим: шифруем для сервера и для всех пиров
                server_payload, peer_payloads = self._e2e_manager.encrypt_for_all(text)

                await send_message(self.writer, {
                    "type": "chat",
                    "server_payload": base64.b64encode(server_payload).decode('ascii'),
                    "peer_payloads": {
                        pid: base64.b64encode(p).decode('ascii')
                        for pid, p in peer_payloads.items()
                    },
                    "nonce": base64.b64encode(
                        self._nonce_checker.create_nonce()
                    ).decode('ascii')
                })
            else:
                # Обычный режим
                ciphertext = self.session.encrypt(text)
                await send_message(self.writer, {
                    "type": "chat",
                    "payload": base64.b64encode(ciphertext).decode('ascii'),
                    "nonce": base64.b64encode(
                        self._nonce_checker.create_nonce()
                    ).decode('ascii')
                })

            self.ui.add_message(text, 'me', self.ui.my_nickname)

        except Exception as e:
            self.ui.add_system(f"Failed to send message: {e}")
            logger.error("Send error: %s", e)
