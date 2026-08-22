"""Инвайт-строки: один токен вместо копирования hex и правки ростера.

Формат приглашения участника::

    p2pchat:MAGIC(4) ver(1) ключ(32) флаги(1) порт(2) хост ник контрольная(4) -> base32

Приглашение группы — то же самое, но внутри сжатый ростер целиком.

Base32 выбран сознательно: его алфавит (A–Z, 2–7) не содержит нуля, единицы и
восьмёрки, поэтому строку можно продиктовать голосом, не поясняя «ноль или
буква О». Контрольная сумма ловит опечатку сразу, а не через час отладки
«почему не соединяется».

**Важно про безопасность.** Инвайт содержит публичный ключ. Если он идёт через
канал, который контролирует противник, ключ подменяется — и вы установите
безупречно защищённое соединение не с тем человеком. Инвайт удобен, но это
по-прежнему TOFU: он не отменяет сверку отпечатка или SAS голосом. Поэтому
разбор инвайта всегда возвращает отпечаток, чтобы вызывающий код мог его
показать.
"""

from __future__ import annotations

import base64
import gzip
import json
from dataclasses import dataclass

from ..crypto import primitives as p
from ..crypto.identity import fingerprint
from .roster import Member, Roster

PEER_PREFIX = "p2pchat:"
GROUP_PREFIX = "p2pchat-group:"
PEER_MAGIC = b"P2PI"
GROUP_MAGIC = b"P2PG"
VERSION = 1
CHECKSUM_LEN = 4
FLAG_BOT = 0x01

MAX_HOST_LEN = 255
MAX_NICK_LEN = 32
MAX_INVITE_CHARS = 8192


class InviteError(Exception):
    """Строка приглашения не разбирается: не тот формат, версия или опечатка."""


@dataclass(frozen=True)
class Invite:
    """Разобранное приглашение участника."""

    member: Member

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.member.public)


def _checksum(payload: bytes) -> bytes:
    return p.hash_(b"p2pchat-invite-v1" + payload)[:CHECKSUM_LEN]


def _encode(magic: bytes, payload: bytes, prefix: str) -> str:
    blob = magic + bytes([VERSION]) + payload
    blob += _checksum(blob)
    return prefix + base64.b32encode(blob).decode("ascii").rstrip("=")


def _decode(text: str, magic: bytes, prefix: str) -> bytes:
    text = text.strip()
    if len(text) > MAX_INVITE_CHARS:
        raise InviteError("строка приглашения неправдоподобно длинная")
    if not text.startswith(prefix):
        raise InviteError(f"строка должна начинаться с {prefix}")

    body = text[len(prefix) :].strip().replace(" ", "").replace("\n", "").upper()
    padded = body + "=" * (-len(body) % 8)
    try:
        blob = base64.b32decode(padded)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise InviteError("строка испорчена при копировании") from exc

    # В base32 последний символ несёт неиспользуемые биты: несколько разных
    # строк декодируются в одни и те же байты. Опечатка ровно в этом месте
    # прошла бы мимо контрольной суммы, поэтому требуем каноничную запись.
    if base64.b32encode(blob).decode("ascii").rstrip("=") != body:
        raise InviteError("строка испорчена при копировании")

    if len(blob) < len(magic) + 1 + CHECKSUM_LEN:
        raise InviteError("строка обрезана")
    if blob[: len(magic)] != magic:
        raise InviteError("это приглашение другого вида")
    if blob[len(magic)] != VERSION:
        raise InviteError(f"неподдерживаемая версия приглашения: {blob[len(magic)]}")

    payload, checksum = blob[:-CHECKSUM_LEN], blob[-CHECKSUM_LEN:]
    if _checksum(payload) != checksum:
        raise InviteError("контрольная сумма не сошлась — в строке опечатка")
    return payload[len(magic) + 1 :]


# --- приглашение участника ---------------------------------------------------


def encode_peer(member: Member) -> str:
    nick = member.nick.encode("utf-8")[:MAX_NICK_LEN]
    host = (member.host or "").encode("utf-8")[:MAX_HOST_LEN]
    flags = FLAG_BOT if member.is_bot else 0
    payload = (
        member.public
        + bytes([flags])
        + (member.port or 0).to_bytes(2, "big")
        + bytes([len(host)])
        + host
        + bytes([len(nick)])
        + nick
    )
    return _encode(PEER_MAGIC, payload, PEER_PREFIX)


def decode_peer(text: str) -> Invite:
    payload = _decode(text, PEER_MAGIC, PEER_PREFIX)
    try:
        public = payload[:32]
        flags = payload[32]
        port = int.from_bytes(payload[33:35], "big")
        offset = 35
        host_len = payload[offset]
        offset += 1
        host = payload[offset : offset + host_len].decode("utf-8")
        offset += host_len
        nick_len = payload[offset]
        offset += 1
        nick = payload[offset : offset + nick_len].decode("utf-8")
        offset += nick_len
    except (IndexError, UnicodeDecodeError) as exc:
        raise InviteError("приглашение повреждено") from exc

    if offset != len(payload):
        raise InviteError("в приглашении лишние байты")
    if len(public) != 32:
        raise InviteError("некорректный ключ в приглашении")
    if not nick:
        raise InviteError("в приглашении пустой ник")

    return Invite(
        member=Member(
            nick=nick,
            public=public,
            host=host or None,
            port=port or None,
            is_bot=bool(flags & FLAG_BOT),
        )
    )


# --- приглашение группы ------------------------------------------------------


def encode_group(roster: Roster) -> str:
    raw = json.dumps(roster.to_json(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _encode(GROUP_MAGIC, gzip.compress(raw, 9), GROUP_PREFIX)


def decode_group(text: str) -> Roster:
    payload = _decode(text, GROUP_MAGIC, GROUP_PREFIX)
    try:
        raw = json.loads(gzip.decompress(payload).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise InviteError("не удалось развернуть приглашение группы") from exc
    return Roster.from_json(raw)


def looks_like_group(text: str) -> bool:
    return text.strip().startswith(GROUP_PREFIX)
