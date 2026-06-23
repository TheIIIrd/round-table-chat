"""
Стандартные команды чата: /nick, /users, /help, /quit, /clear.

Перенесены из CommandHandler в плагинную систему.
"""

from client.plugins.base import PluginBase, PluginAPI
from utils.validators import validate_nickname
from utils.logging_config import get_logger

logger = get_logger(__name__)


class BuiltinPlugin(PluginBase):
    name = "core"
    commands = {
        "/nick":  "Change nickname: /nick <name>",
        "/users": "List online users",
        "/clear": "Clear chat history",
        "/quit":  "Exit the chat",
        "/exit":  "Exit the chat",
        "/help":  "Show available commands",
    }

    def __init__(self, api: PluginAPI):
        super().__init__(api)

    async def handle_command(self, command: str, args: str) -> bool:
        handlers = {
            "/nick":  self._cmd_nick,
            "/users": self._cmd_users,
            "/help":  self._cmd_help,
            "/quit":  self._cmd_quit,
            "/exit":  self._cmd_quit,
            "/clear": self._cmd_clear,
        }

        handler = handlers.get(command)
        if handler:
            await handler(args)
            return True
        return False

    async def _cmd_nick(self, args: str) -> None:
        new_nick = args.strip()

        is_valid, error = validate_nickname(new_nick)
        if not is_valid:
            self.api.send_plugin_message(self.name, f"Invalid nickname: {error}")
            return

        if new_nick in self.api.online_users:
            self.api.send_plugin_message(self.name, f"Nickname '{new_nick}' is already taken")
            return

        if new_nick == self.api.my_nickname:
            self.api.send_plugin_message(self.name, "That's already your nickname, dumbass")
            return

        old_nick = self.api.my_nickname
        self.api.change_nickname(new_nick)

        if self.api.connected:
            try:
                await self.api.send_nickname_change(old_nick, new_nick)
                logger.info("Nickname change sent: %s -> %s", old_nick, new_nick)
            except Exception as e:
                logger.error("Failed to send nickname change: %s", e)
                self.api.send_plugin_message(self.name, f"Failed to change nickname: {e}")
                self.api.change_nickname(old_nick)  # Откат
        else:
            self.api.send_plugin_message(self.name, f"Nickname changed to '{new_nick}' (offline)")

    async def _cmd_users(self, args: str) -> None:
        users = self.api.online_users
        if users:
            user_list = ", ".join(f"@{u}" for u in users)
            self.api.send_plugin_message(self.name, f"Online ({len(users)}): {user_list}")
        else:
            self.api.send_plugin_message(self.name, "No users online (you're alone, buddy)")

    async def _cmd_help(self, args: str) -> None:
        # Доступ к plugin_manager только для builtin-плагина через _client
        help_lines = self.api._client.plugin_manager.get_help()
        for line in help_lines:
            self.api.send_system(line)

    async def _cmd_quit(self, args: str) -> None:
        self.api.send_plugin_message(self.name, "Goodbye!")
        self.api._client.ui.running = False

    async def _cmd_clear(self, args: str) -> None:
        self.api._client.ui.clear_history()
        self.api.send_plugin_message(self.name, "Chat history cleared")
