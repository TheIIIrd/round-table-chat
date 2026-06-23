"""
Базовый класс для всех плагинов чат-клиента.

Жизненный цикл:
1. __init__(client) — создаётся при старте
2. on_connect() — после успешного handshake
3. on_disconnect() — при отключении
4. handle_command(cmd, args) — при вводе команды
5. on_message(sender, text) — при получении любого сообщения
"""

from abc import ABC
from typing import TYPE_CHECKING

from core.protocol import send_message

if TYPE_CHECKING:
    from client.client import ChatClient


class PluginAPI:
    """
    Безопасный API для плагинов.
    Не даёт доступа к writer, session, паролям и внутренностям.
    """

    def __init__(self, client: 'ChatClient'):
        self._client = client

    @property
    def my_nickname(self) -> str:
        return self._client.ui.my_nickname

    @property
    def online_users(self) -> list[str]:
        return list(self._client.ui.online_users)

    @property
    def connected(self) -> bool:
        return self._client.ui.connected

    def send_system(self, text: str) -> None:
        """Показать сообщение только в своём UI."""
        self._client.ui.add_system(text)

    def send_plugin_message(self, plugin_name: str, text: str) -> None:
        """Показать сообщение от имени плагина."""
        self._client.ui.add_system(f"[{plugin_name}] {text}")

    async def send_chat(self, text: str) -> None:
        """Отправить сообщение в общий чат."""
        # Используем публичный метод send_text, а не writer напрямую
        await self._client.send_text(text)

    def get_user_list(self) -> list[str]:
        """Список пользователей онлайн."""
        return list(self._client.ui.online_users)

    def change_nickname(self, new_nick: str) -> None:
        """Сменить никнейм (только для доверенных плагинов)."""
        self._client.ui.my_nickname = new_nick

    async def send_nickname_change(self, old_nick: str, new_nick: str) -> None:
        """Отправить запрос на смену ника серверу."""
        if self._client.writer and self._client.session and self._client.session.ready:
            await send_message(self._client.writer, {
                "type": "nickname_change",
                "old_nickname": old_nick,
                "new_nickname": new_nick
            })


class PluginBase(ABC):
    """Базовый класс плагина."""

    # Уникальное имя (для логов)
    name: str = "base"

    # Словарь команд: {"/cmd": "описание для /help"}
    commands: dict[str, str] = {}

    def __init__(self, api: PluginAPI):
        self.api = api
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    # Хуки жизненного цикла

    async def on_connect(self) -> None:
        """Вызывается после успешного подключения к серверу."""

    async def on_disconnect(self) -> None:
        """Вызывается при отключении от сервера."""

    # Обработка команд

    async def handle_command(self, command: str, args: str) -> bool:
        """
        Обрабатывает команду.

        Args:
            command: команда со слешем, например '/roll'
            args: всё что после команды, например '2d6'

        Returns:
            True — команда обработана (не передавать дальше)
            False — команда не распознана
        """
        return False

    # Обработка сообщений

    async def on_message(self, sender_nick: str, text: str) -> None:
        """
        Вызывается при получении ЛЮБОГО сообщения.
        Плагин может анализировать чат и реагировать.
        """
