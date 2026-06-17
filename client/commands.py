"""
Command handler for chat client.
Обрабатывает команды типа /nick, /users, /quit и т.д.
"""

from typing import TYPE_CHECKING

from core.protocol import send_message
from utils.validators import validate_nickname
from utils.logging_config import get_logger

if TYPE_CHECKING:
    from client.client import ChatClient

logger = get_logger(__name__)


class CommandHandler:
    """
    Обработчик клиентских команд (строки, начинающиеся с /).

    Вынесен отдельно, чтобы не раздувать ChatClient и
    можно было тестировать команды без сетевого соединения.
    """

    def __init__(self, client: 'ChatClient'):
        self.client = client

    async def handle(self, text: str) -> bool:
        """
        Парсит и выполняет команду.

        Returns:
            True — команда обработана (не отправлять как сообщение)
            False — это не команда (отправлять как обычный текст)
        """
        if not text.startswith('/'):
            return False

        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handlers = {
            '/nick': self._cmd_nick,
            '/users': self._cmd_users,
            '/help': self._cmd_help,
            '/quit': self._cmd_quit,
            '/exit': self._cmd_quit,
            '/clear': self._cmd_clear,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler(args)
        else:
            self.client.ui.add_system(f"Unknown command: {cmd}. Type /help for available commands")

        return True

    async def _cmd_nick(self, args: str) -> None:
        """Смена никнейма: /nick new_name"""
        new_nick = args.strip()

        is_valid, error = validate_nickname(new_nick)
        if not is_valid:
            self.client.ui.add_system(f"Invalid nickname: {error}")
            return

        # Проверяем уникальность на клиенте (сервер тоже должен проверять)
        if new_nick in self.client.ui.online_users:
            self.client.ui.add_system(f"Nickname '{new_nick}' is already taken")
            return

        if new_nick == self.client.ui.my_nickname:
            self.client.ui.add_system("That's already your nickname, dumbass")
            return

        old_nick = self.client.ui.my_nickname
        self.client.ui.my_nickname = new_nick

        # Отправляем серверу, если подключены
        if self.client.writer and self.client.session and self.client.session.ready:
            try:
                await send_message(self.client.writer, {
                    "type": "nickname_change",
                    "old_nickname": old_nick,
                    "new_nickname": new_nick
                })
                logger.info("Nickname change sent: %s -> %s", old_nick, new_nick)
            except Exception as e:
                logger.error("Failed to send nickname change: %s", e)
                self.client.ui.add_system(f"Failed to change nickname: {e}")
                # Откатываем
                self.client.ui.my_nickname = old_nick
        else:
            self.client.ui.add_system(f"Nickname changed to '{new_nick}' (offline)")

    async def _cmd_users(self, args: str) -> None:
        """Показывает список онлайн-пользователей."""
        users = self.client.ui.online_users
        if users:
            user_list = ", ".join(f"@{u}" for u in users)
            self.client.ui.add_system(f"Online ({len(users)}): {user_list}")
        else:
            self.client.ui.add_system("No users online (you're alone, buddy)")

    async def _cmd_help(self, args: str) -> None:
        """Показывает справку по командам."""
        help_lines = [
            "=== Commands ===",
            "/nick <name>  — Change your nickname (1-20 chars: a-z, 0-9, _, -)",
            "/users        — List online users",
            "/clear        — Clear chat history",
            "/quit, /exit  — Exit the chat",
            "/help         — Show this help",
        ]
        for line in help_lines:
            self.client.ui.add_system(line)

    async def _cmd_quit(self, args: str) -> None:
        """Выход из чата."""
        self.client.ui.add_system("Goodbye!")
        self.client.ui.running = False

    async def _cmd_clear(self, args: str) -> None:
        """Очистка истории сообщений."""
        self.client.ui.clear_history()
        self.client.ui.add_system("Chat history cleared")
