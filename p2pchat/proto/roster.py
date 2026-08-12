"""Состав группы.

Идентификатор группы = BLAKE2b от отсортированных публичных ключей участников.
Это даёт полезное свойство: каждый вычисляет его сам, и любая правка состава
меняет id. Поскольку id входит в prologue хендшейка, участник с подменённым
ростером просто не сойдётся с остальными — расхождение обнаруживается на
установке соединения, а не после.

Состав статичен: добавить человека = раздать новый файл ростера и получить
новую группу. Динамическое членство потребовало бы решать, кто вправе
приглашать и как остальные проверяют это право, — отдельная задача, которую
лучше не делать наполовину.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

MAX_MEMBERS = 8
GROUP_ID_LEN = 16


class RosterError(Exception):
    """Файл ростера некорректен."""


@dataclass(frozen=True)
class Member:
    nick: str
    public: bytes
    host: str | None = None
    port: int | None = None
    is_bot: bool = False

    @property
    def address(self) -> tuple[str, int] | None:
        if self.host and self.port:
            return self.host, self.port
        return None

    def to_json(self) -> dict:
        item: dict = {"nick": self.nick, "key": self.public.hex()}
        if self.host and self.port:
            item["address"] = f"{self.host}:{self.port}"
        if self.is_bot:
            item["bot"] = True
        return item


@dataclass(frozen=True)
class Roster:
    name: str
    members: tuple[Member, ...]

    @property
    def group_id(self) -> bytes:
        material = b"".join(sorted(member.public for member in self.members))
        return hashlib.blake2b(material, digest_size=GROUP_ID_LEN).digest()

    def by_key(self, public: bytes) -> Member | None:
        for member in self.members:
            if member.public == public:
                return member
        return None

    def by_nick(self, nick: str) -> Member | None:
        for member in self.members:
            if member.nick == nick:
                return member
        return None

    def others(self, me: bytes) -> tuple[Member, ...]:
        return tuple(member for member in self.members if member.public != me)

    @classmethod
    def load(cls, path: str | Path) -> "Roster":
        try:
            raw = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RosterError(f"не читается файл ростера: {exc}") from exc
        return cls.from_json(raw)

    @classmethod
    def from_json(cls, raw: dict) -> "Roster":
        entries = raw.get("members")
        if not isinstance(entries, list) or not entries:
            raise RosterError("в ростере нет участников")
        if len(entries) > MAX_MEMBERS:
            raise RosterError(
                f"участников больше {MAX_MEMBERS}: попарный меш столько не потянет"
            )

        members = []
        for item in entries:
            nick = str(item.get("nick", "")).strip()
            if not nick:
                raise RosterError("у участника пустой ник")
            try:
                public = bytes.fromhex(item["key"])
            except (KeyError, ValueError) as exc:
                raise RosterError(f"некорректный ключ у {nick}: {exc}") from exc
            if len(public) != 32:
                raise RosterError(f"ключ {nick} должен быть 32 байта")
            host, port = _parse_address(item.get("address"), nick)
            members.append(
                Member(nick=nick, public=public, host=host, port=port, is_bot=bool(item.get("bot")))
            )

        nicks = [m.nick for m in members]
        if len(set(nicks)) != len(nicks):
            raise RosterError("ники участников должны быть уникальны")
        keys = [m.public for m in members]
        if len(set(keys)) != len(keys):
            raise RosterError("один и тот же ключ указан дважды")

        return cls(name=str(raw.get("name", "group")), members=tuple(members))

    def to_json(self) -> dict:
        return {"name": self.name, "members": [m.to_json() for m in self.members]}

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_json(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def with_member(self, member: Member) -> "Roster":
        if self.by_nick(member.nick) or self.by_key(member.public):
            raise RosterError(f"участник {member.nick} уже в ростере")
        return Roster(name=self.name, members=self.members + (member,))


def _parse_address(value: object, nick: str) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    text = str(value)
    host, _, port_text = text.rpartition(":")
    if not host or not port_text.isdigit():
        raise RosterError(f"адрес {nick} должен быть в виде host:port, получено {text!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise RosterError(f"порт {nick} вне диапазона")
    return host, port
