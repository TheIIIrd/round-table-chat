"""UI module: terminal interface and message rendering."""

from ui.message_model import Message
from ui.colors import init_colors, get_nickname_color_index, get_color_pair, PAIR_SYSTEM_MSG, PAIR_PROMPT, PAIR_STATUS_BAR
from ui.chat_ui import ChatUI

__all__ = [
    'Message',
    'ChatUI',
    'init_colors',
    'get_nickname_color_index',
    'get_color_pair',
    'PAIR_SYSTEM_MSG',
    'PAIR_PROMPT',
    'PAIR_STATUS_BAR',
]
