"""События, которые меш отдаёт наружу.

Интерфейс и бот получают одни и те же события и различаются только реакцией.
Чтобы UI не превращался в лестницу из ``isinstance``, каждое событие само
умеет себя показать.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..format import sanitize


class Event:
    """Базовое событие.

    ``render`` даёт чёрно-белый текст: он должен оставаться понятным там, где
    цвета нет. Раскрашивает вывод консоль, а не событие.
    """

    def render(self) -> str:  # pragma: no cover - переопределяется
        return self.__class__.__name__


@dataclass
class PeerConnected(Event):
    nick: str
    public: bytes
    sas: str
    verified: bool

    def render(self) -> str:
        if self.verified:
            return f"→ {self.nick} на связи (отпечаток сверен ранее)"
        return (
            f"→ {self.nick} на связи\n"
            f"  SAS: {self.sas}\n"
            f"  Сверьте код голосом и введите /verify {self.nick}"
        )


@dataclass
class PeerDisconnected(Event):
    nick: str
    reason: str

    def render(self) -> str:
        return f"← {self.nick} отключился ({self.reason})"


@dataclass
class TextMessage(Event):
    nick: str
    public: bytes
    text: str
    lamport: int
    is_bot: bool = False

    def render(self) -> str:
        text = sanitize(self.text)
        if self.is_bot:
            return "\n".join(f"┃ {line}" for line in text.split("\n"))
        return f"{self.nick}: {text}"


@dataclass
class Notice(Event):
    text: str

    def render(self) -> str:
        return f"· {self.text}"


@dataclass
class Alert(Event):
    text: str

    def render(self) -> str:
        return f"⚠ ВНИМАНИЕ: {self.text}"


@dataclass
class FileOffered(Event):
    nick: str
    transfer_id: str
    name: str
    size: int

    def render(self) -> str:
        return (
            f"↓ {self.nick} предлагает файл «{sanitize(self.name)}» ({self.size} байт)\n"
            f"  /accept {self.transfer_id}   /decline {self.transfer_id}"
        )


@dataclass
class FileFinished(Event):
    nick: str
    name: str
    path: Path

    def render(self) -> str:
        return f"✓ файл «{sanitize(self.name)}» от {self.nick} принят и проверен: {self.path}"


@dataclass
class FileFailed(Event):
    nick: str
    name: str
    reason: str

    def render(self) -> str:
        return f"✗ передача «{sanitize(self.name)}» ({self.nick}) не удалась: {self.reason}"


@dataclass
class FileSent(Event):
    nick: str
    name: str

    def render(self) -> str:
        return f"✓ файл «{sanitize(self.name)}» отправлен участнику {self.nick}"
