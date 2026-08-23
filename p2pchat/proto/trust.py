"""Список известных пиров: TOFU и отметка о сверке SAS.

Noise_XX доказывает владение ключом, но не отвечает на вопрос «чей это ключ».
Ответ даёт человек — один раз, сверив SAS голосом. Здесь этот ответ хранится,
чтобы не переспрашивать при каждом соединении.

Записи хранятся **по публичному ключу**, а не по нику. Личность — это ключ; ник
лишь ярлык, который человек может сменить, а посторонний — присвоить. Пока
ключом словаря был ник, смена ника стирала отметку о сверке, а чужак, назвавшийся
знакомым именем, вызывал у вас тревогу о «подмене ключа» на пустом месте.

Ключевой сценарий — под знакомым ником приходит другой ключ. Это либо
переустановка у собеседника, либо атака. Отличить их программа не может, поэтому
она не гадает: соединение отвергается, а решение остаётся человеку.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..crypto.identity import fingerprint


class TrustDecision(Enum):
    NEW = "new"  # ключ видим впервые
    KNOWN = "known"  # ключ знаком, SAS ещё не сверялся
    VERIFIED = "verified"  # ключ знаком и был сверен человеком
    NICK_TAKEN = "nick_taken"  # под этим ником уже известен ДРУГОЙ ключ


@dataclass
class PeerRecord:
    nick: str
    key: str  # публичный ключ в hex
    verified: bool = False
    note: str = ""
    address: str | None = None  # последний адрес, по которому связь получилась

    def to_json(self) -> dict:
        item = {"nick": self.nick, "key": self.key, "verified": self.verified, "note": self.note}
        if self.address:
            item["address"] = self.address
        return item

    @property
    def endpoint(self) -> tuple[str, int] | None:
        if not self.address:
            return None
        host, _, port = self.address.rpartition(":")
        return (host, int(port)) if host and port.isdigit() else None


@dataclass
class TrustStore:
    path: Path
    peers: dict[str, PeerRecord] = field(default_factory=dict)  # ключ в hex -> запись

    @classmethod
    def load(cls, path: str | Path) -> "TrustStore":
        path = Path(path)
        if not path.exists():
            return cls(path=path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"список известных пиров повреждён: {exc}") from exc
        peers = {
            item["key"]: PeerRecord(
                nick=item["nick"],
                key=item["key"],
                verified=bool(item.get("verified", False)),
                note=item.get("note", ""),
                address=item.get("address"),
            )
            for item in raw.get("peers", [])
        }
        return cls(path=path, peers=peers)

    def save(self) -> None:
        payload = {"peers": [record.to_json() for record in self.peers.values()]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def by_key(self, public: bytes) -> PeerRecord | None:
        return self.peers.get(public.hex())

    def by_nick(self, nick: str) -> PeerRecord | None:
        for record in self.peers.values():
            if record.nick == nick:
                return record
        return None

    def check(self, public: bytes, nick: str = "") -> TrustDecision:
        record = self.by_key(public)
        if record is not None:
            return TrustDecision.VERIFIED if record.verified else TrustDecision.KNOWN
        if nick and self.by_nick(nick) is not None:
            return TrustDecision.NICK_TAKEN
        return TrustDecision.NEW

    def remember(self, public: bytes, nick: str, *, verified: bool = False) -> PeerRecord:
        record = PeerRecord(nick=nick, key=public.hex(), verified=verified)
        self.peers[record.key] = record
        self.save()
        return record

    def remember_address(self, public: bytes, host: str, port: int) -> None:
        """Сохраняет адрес, по которому связь действительно получилась.

        Благодаря этому ростер нужен ради ключей, а не ради адресов: сменившийся
        IP перестаёт требовать, чтобы все переписали файл.
        """
        record = self.by_key(public)
        if record is None:
            return
        address = f"{host}:{port}"
        if record.address == address:
            return
        record.address = address
        self.save()

    def mark_verified(self, nick: str) -> bool:
        record = self.by_nick(nick)
        if record is None:
            return False
        record.verified = True
        self.save()
        return True

    def forget(self, nick: str) -> bool:
        record = self.by_nick(nick)
        if record is None:
            return False
        self.peers.pop(record.key, None)
        self.save()
        return True

    def describe(self, nick: str) -> str:
        record = self.by_nick(nick)
        if record is None:
            return f"{nick}: неизвестен"
        mark = "сверен" if record.verified else "НЕ сверен"
        return f"{nick}: {fingerprint(bytes.fromhex(record.key))} ({mark})"
