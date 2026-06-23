"""Client module: network client, plugin system, and command handling."""

from client.client import ChatClient
from client.plugin_manager import PluginManager
from client.plugins.base import PluginBase

__all__ = ['ChatClient', 'PluginManager', 'PluginBase']
