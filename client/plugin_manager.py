"""
Загружает плагины и диспатчит команды.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

from client.plugins.base import PluginBase, PluginAPI
from utils.logging_config import get_logger

if TYPE_CHECKING:
    from client.client import ChatClient

logger = get_logger(__name__)


class PluginManager:
    """Загружает, управляет и диспатчит плагины."""

    def __init__(self, client: 'ChatClient'):
        self.client = client
        self._plugins: list[PluginBase] = []
        self._command_map: dict[str, PluginBase] = {}

    def load_builtin(self) -> None:
        import client.plugins as pkg
        logger.info("Loading plugins from %s", pkg.__path__)

        for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            logger.info("Found module: %s", module_name)
            if module_name in ('base', '__init__'):
                continue
            try:
                module = importlib.import_module(f"client.plugins.{module_name}")
                self._load_from_module(module)
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", module_name, e)

        logger.info("Command map: %s", list(self._command_map.keys()))

    def _load_from_module(self, module) -> None:
        """Ищет PluginBase-классы в модуле и регистрирует их."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, PluginBase)
                and attr is not PluginBase
            ):
                api = PluginAPI(self.client)
                plugin = attr(api)

                self._plugins.append(plugin)

                for cmd in plugin.commands:
                    self._command_map[cmd] = plugin
                logger.debug(
                    "Loaded plugin: %s (%d commands)",
                    plugin.name,
                    len(plugin.commands),
                )

    async def handle_command(self, text: str) -> bool:
        """Диспатчит команду нужному плагину. True — обработано."""
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        plugin = self._command_map.get(cmd)
        if plugin and plugin.enabled:
            try:
                return await plugin.handle_command(cmd, args)
            except Exception as e:
                logger.error("Plugin %s error on %s: %s", plugin.name, cmd, e)
                plugin.api.send_plugin_message(plugin.name, f"Error: {e}")
                return True
        return False

    async def on_connect(self) -> None:
        for p in self._plugins:
            try:
                await p.on_connect()
            except Exception as e:
                logger.error("Plugin %s on_connect error: %s", p.name, e)

    async def on_disconnect(self) -> None:
        for p in self._plugins:
            try:
                await p.on_disconnect()
            except Exception as e:
                logger.error("Plugin %s on_disconnect error: %s", p.name, e)

    async def on_message(self, sender_nick: str, text: str) -> None:
        for p in self._plugins:
            if p.enabled:
                try:
                    await p.on_message(sender_nick, text)
                except Exception as e:
                    logger.error("Plugin %s on_message error: %s", p.name, e)

    def get_help(self) -> list[str]:
        """Собирает справку со всех плагинов."""
        lines = ["=== Commands ==="]
        for plugin in self._plugins:
            if plugin.enabled and plugin.commands:
                for cmd, desc in plugin.commands.items():
                    lines.append(f"{cmd:<14} — {desc}")
        return lines
