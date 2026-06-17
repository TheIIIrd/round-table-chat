"""Message model for chat UI. Отделяем данные от представления."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


# Кто отправил сообщение: сам пользователь, другой юзер, или система
SenderType = Literal['me', 'peer', 'system']


@dataclass
class Message:
    """Одно сообщение в истории чата."""
    text: str
    sender: SenderType
    nickname: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_system(self) -> bool:
        return self.sender == 'system'

    @property
    def is_mine(self) -> bool:
        return self.sender == 'me'

    @property
    def is_peer(self) -> bool:
        return self.sender == 'peer'

    def format_timestamp(self, fmt: str = "%H:%M:%S") -> str:
        """Форматирует временную метку для отображения."""
        return self.timestamp.strftime(fmt)
