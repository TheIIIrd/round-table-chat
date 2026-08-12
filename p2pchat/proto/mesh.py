"""Попарный меш: по одной защищённой сессии с каждым участником.

Групповое сообщение шифруется отдельно для каждого получателя. Трафик растёт
линейно по числу участников, зато свойства безопасности ровно те же, что у
разговора один на один: никаких общих групповых ключей, которые надо было бы
менять при уходе участника.

**Кто кому звонит.** Если оба пира одновременно подключатся друг к другу,
получатся две сессии вместо одной. Правило простое: звонит тот, чей публичный
ключ меньше. Ключи различны и упорядочены одинаково у обеих сторон, так что
договариваться не нужно. Исключение — участник без своего адреса: ему звонить
некуда, поэтому звонит он. На случай гонки есть и проверка при приёме.

**Кого пускаем.** В групповом режиме ключ обязан быть в ростере — он там
зафиксирован, поэтому подмена ключа участника невозможна в принципе, а не
обнаруживается постфактум. В режиме один на один ростера нет, и работает TOFU:
первый ключ запоминается, несовпадение при следующем соединении — отказ.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from pathlib import Path

from ..crypto.identity import Identity, fingerprint
from ..net.link import Link, LinkClosed
from ..net.tcp import TcpLink, serve
from . import events as ev
from .envelope import (
    TYPE_FILE_ACCEPT,
    TYPE_FILE_CHUNK,
    TYPE_FILE_DECLINE,
    TYPE_FILE_DONE,
    TYPE_FILE_OFFER,
    TYPE_PRESENCE,
    TYPE_TEXT,
    Envelope,
    EnvelopeError,
    LamportClock,
    make,
)
from .files import (
    IncomingTransfer,
    OutgoingTransfer,
    TransferError,
    decode_id,
)
from .roster import Member, Roster
from .session import Session, SessionError, build_prologue
from .trust import TrustDecision, TrustStore

RECONNECT_DELAY = 5.0
MAX_NICK_LEN = 32


@dataclass
class Connection:
    member: Member
    session: Session
    reader: asyncio.Task

    @property
    def nick(self) -> str:
        return self.member.nick


class Mesh:
    """Соединения со всеми участниками и обмен прикладными сообщениями."""

    def __init__(
        self,
        identity: Identity,
        *,
        nickname: str,
        roster: Roster | None,
        trust: TrustStore,
        download_dir: Path,
        listen: tuple[str, int] | None = None,
    ) -> None:
        self.identity = identity
        self.nickname = nickname[:MAX_NICK_LEN]
        self.roster = roster
        self.trust = trust
        self.download_dir = Path(download_dir)
        self.listen = listen

        self.events: asyncio.Queue = asyncio.Queue()
        self.clock = LamportClock()
        self._connections: dict[bytes, Connection] = {}
        self._incoming: dict[bytes, tuple[bytes, IncomingTransfer]] = {}
        self._outgoing: dict[bytes, OutgoingTransfer] = {}
        self._tasks: set[asyncio.Task] = set()
        self._server: asyncio.Server | None = None
        self._running = False

    # --- жизненный цикл -------------------------------------------------------

    @property
    def group_id(self) -> bytes:
        return self.roster.group_id if self.roster else b""

    @property
    def prologue(self) -> bytes:
        mode = "mesh" if self.roster else "direct"
        return build_prologue(mode=mode, group_id=self.group_id)

    @property
    def peers(self) -> list[str]:
        return sorted(conn.nick for conn in self._connections.values())

    async def start(self) -> None:
        self._running = True
        if self.listen is not None:
            host, port = self.listen
            self._server = await serve(host, port, self._on_inbound)
            actual = self._server.sockets[0].getsockname()[1]
            self.listen = (host, actual)
            await self._emit(ev.Notice(f"слушаю {host}:{actual}"))
        if self.roster is not None:
            self._spawn(self._dial_loop())

    async def stop(self) -> None:
        self._running = False
        for task in list(self._tasks):
            task.cancel()
        for conn in list(self._connections.values()):
            conn.reader.cancel()
            await conn.session.close()
        self._connections.clear()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    # --- исходящие соединения -------------------------------------------------

    async def connect_to(self, host: str, port: int) -> None:
        """Явное подключение (режим один на один или ручной вызов)."""
        try:
            link = await TcpLink.connect(host, port)
            session = await Session.initiate(
                link,
                self.identity,
                prologue=self.prologue,
                payload=self.nickname.encode("utf-8"),
            )
        except (LinkClosed, SessionError, Exception) as exc:  # noqa: BLE001
            await self._emit(ev.Notice(f"не удалось соединиться с {host}:{port}: {exc}"))
            return
        await self._register(session, dialed=True)

    def _should_dial(self, member: Member) -> bool:
        if member.address is None:
            return False
        if self.listen is None:
            return True
        return self.identity.public < member.public

    async def _dial_loop(self) -> None:
        assert self.roster is not None
        while self._running:
            for member in self.roster.others(self.identity.public):
                if member.public in self._connections or not self._should_dial(member):
                    continue
                host, port = member.address  # type: ignore[misc]
                try:
                    link = await TcpLink.connect(host, port)
                    session = await Session.initiate(
                        link,
                        self.identity,
                        prologue=self.prologue,
                        payload=self.nickname.encode("utf-8"),
                    )
                except Exception:  # noqa: BLE001 — пир просто ещё не поднялся
                    continue
                await self._register(session, dialed=True)
            await asyncio.sleep(RECONNECT_DELAY)

    async def _on_inbound(self, link: TcpLink) -> None:
        try:
            session = await Session.accept(
                link,
                self.identity,
                prologue=self.prologue,
                payload=self.nickname.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001
            await self._emit(ev.Notice(f"входящее соединение отклонено: {exc}"))
            return
        await self._register(session, dialed=False)
        conn = self._connections.get(session.remote_static)
        if conn is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await conn.reader

    # --- регистрация и проверка доверия ---------------------------------------

    async def _register(self, session: Session, *, dialed: bool) -> None:
        public = session.remote_static
        member = await self._authorize(session, public)
        if member is None:
            await session.close()
            return

        if public in self._connections:
            # Гонка: пир позвонил одновременно с нами. Оставляем ту сессию,
            # где звонил обладатель меньшего ключа.
            await self._emit(ev.Notice(f"повторное соединение с {member.nick} закрыто"))
            await session.close()
            return

        decision = self.trust.check(member.nick, public)
        if decision is TrustDecision.NEW:
            self.trust.remember(member.nick, public)

        reader = asyncio.create_task(self._read_peer(member, session))
        self._connections[public] = Connection(member=member, session=session, reader=reader)

        await self._emit(
            ev.PeerConnected(
                nick=member.nick,
                public=public,
                sas=session.sas,
                verified=decision is TrustDecision.VERIFIED,
            )
        )
        await self._send_to_session(session, make(TYPE_PRESENCE, self.clock, self.nickname.encode()))

    async def _authorize(self, session: Session, public: bytes) -> Member | None:
        """Решает, кого пускать, и возвращает участника с его ником."""
        if self.roster is not None:
            member = self.roster.by_key(public)
            if member is None:
                await self._emit(
                    ev.Alert(
                        "соединение с ключом, которого нет в ростере: "
                        f"{fingerprint(public)} — отклонено"
                    )
                )
                return None
            return member

        # Режим один на один: ник берём из полезной нагрузки хендшейка.
        raw = session.peer_payload[:MAX_NICK_LEN]
        try:
            nick = raw.decode("utf-8").strip() or fingerprint(public)[:9]
        except UnicodeDecodeError:
            nick = fingerprint(public)[:9]

        decision = self.trust.check(nick, public)
        if decision is TrustDecision.KEY_CHANGED:
            await self._emit(
                ev.Alert(
                    f"у {nick} ДРУГОЙ ключ, чем записан ранее ({fingerprint(public)}). "
                    "Это либо переустановка у собеседника, либо подмена. Соединение "
                    f"отклонено. Если ключ действительно сменился — /forget {nick}"
                )
            )
            return None
        return Member(nick=nick, public=public)

    # --- приём ---------------------------------------------------------------

    async def _read_peer(self, member: Member, session: Session) -> None:
        reason = "соединение закрыто"
        try:
            while True:
                raw = await session.receive()
                try:
                    envelope = Envelope.decode(raw)
                except EnvelopeError as exc:
                    await self._emit(ev.Notice(f"мусор от {member.nick}: {exc}"))
                    continue
                self.clock.observe(envelope.lamport)
                await self._handle(member, session, envelope)
        except asyncio.CancelledError:
            raise
        except LinkClosed as exc:
            reason = str(exc)
        except Exception as exc:  # noqa: BLE001
            reason = f"ошибка: {exc}"
        finally:
            self._connections.pop(member.public, None)
            await session.close()
            self._drop_transfers(member.public)
            await self._emit(ev.PeerDisconnected(member.nick, reason))

    async def _handle(self, member: Member, session: Session, envelope: Envelope) -> None:
        if envelope.type == TYPE_TEXT:
            text = envelope.body.decode("utf-8", errors="replace")
            await self._emit(
                ev.TextMessage(
                    nick=member.nick,
                    public=member.public,
                    text=text,
                    lamport=envelope.lamport,
                    is_bot=member.is_bot,
                )
            )
            return

        if envelope.type == TYPE_PRESENCE:
            return

        try:
            await self._handle_file(member, session, envelope)
        except TransferError as exc:
            await self._emit(ev.FileFailed(member.nick, "", str(exc)))

    async def _handle_file(self, member: Member, session: Session, envelope: Envelope) -> None:
        if envelope.type == TYPE_FILE_OFFER:
            transfer = IncomingTransfer.from_offer(envelope.body, self.download_dir)
            self._incoming[transfer.transfer_id] = (member.public, transfer)
            await self._emit(
                ev.FileOffered(
                    nick=member.nick,
                    transfer_id=transfer.transfer_id.hex()[:8],
                    name=transfer.name,
                    size=transfer.size,
                )
            )
            return

        if envelope.type == TYPE_FILE_ACCEPT:
            transfer_id = decode_id(envelope.body)
            outgoing = self._outgoing.get(transfer_id)
            if outgoing is None:
                return
            self._spawn(self._push_file(member, session, outgoing))
            return

        if envelope.type == TYPE_FILE_DECLINE:
            transfer_id = decode_id(envelope.body)
            outgoing = self._outgoing.pop(transfer_id, None)
            if outgoing is not None:
                await self._emit(ev.FileFailed(member.nick, outgoing.name, "получатель отказался"))
            return

        if envelope.type == TYPE_FILE_CHUNK:
            entry = self._incoming.get(envelope.body[:16])
            if entry is None:
                return
            owner, transfer = entry
            if owner != member.public:
                raise TransferError("кусок пришёл не от того участника")
            transfer.add_chunk(envelope.body)
            return

        if envelope.type == TYPE_FILE_DONE:
            transfer_id = decode_id(envelope.body)
            entry = self._incoming.pop(transfer_id, None)
            if entry is None:
                return
            owner, transfer = entry
            if owner != member.public:
                raise TransferError("завершение пришло не от того участника")
            try:
                path = transfer.finish()
            except TransferError as exc:
                await self._emit(ev.FileFailed(member.nick, transfer.name, str(exc)))
                return
            await self._emit(ev.FileFinished(member.nick, transfer.name, path))

    # --- отправка -------------------------------------------------------------

    async def broadcast(self, text: str) -> None:
        envelope = make(TYPE_TEXT, self.clock, text.encode("utf-8"))
        for conn in list(self._connections.values()):
            await self._send_to_session(conn.session, envelope)

    async def send_text(self, nick: str, text: str) -> bool:
        conn = self._connection_by_nick(nick)
        if conn is None:
            return False
        await self._send_to_session(conn.session, make(TYPE_TEXT, self.clock, text.encode("utf-8")))
        return True

    async def offer_file(self, nick: str, path: str | Path) -> None:
        conn = self._connection_by_nick(nick)
        if conn is None:
            await self._emit(ev.Notice(f"участник {nick} не на связи"))
            return
        try:
            transfer = OutgoingTransfer(path=Path(path))
        except TransferError as exc:
            await self._emit(ev.Notice(str(exc)))
            return
        self._outgoing[transfer.transfer_id] = transfer
        await self._send_to_session(
            conn.session, make(TYPE_FILE_OFFER, self.clock, transfer.offer_body())
        )
        await self._emit(ev.Notice(f"предложил {nick} файл «{transfer.name}», жду ответа"))

    async def respond_to_offer(self, short_id: str, accept: bool) -> None:
        for transfer_id, (owner, transfer) in list(self._incoming.items()):
            if not transfer_id.hex().startswith(short_id):
                continue
            conn = self._connections.get(owner)
            if conn is None:
                self._incoming.pop(transfer_id, None)
                return
            if accept:
                transfer.accept()
                await self._send_to_session(
                    conn.session, make(TYPE_FILE_ACCEPT, self.clock, transfer_id)
                )
            else:
                transfer.decline()
                self._incoming.pop(transfer_id, None)
                await self._send_to_session(
                    conn.session, make(TYPE_FILE_DECLINE, self.clock, transfer_id)
                )
            return
        await self._emit(ev.Notice(f"нет предложения файла с идентификатором {short_id}"))

    async def _push_file(
        self, member: Member, session: Session, transfer: OutgoingTransfer
    ) -> None:
        try:
            for chunk in transfer.chunks():
                await self._send_to_session(session, make(TYPE_FILE_CHUNK, self.clock, chunk))
            await self._send_to_session(
                session, make(TYPE_FILE_DONE, self.clock, transfer.transfer_id)
            )
            await self._emit(ev.FileSent(member.nick, transfer.name))
        except (LinkClosed, SessionError, OSError) as exc:
            await self._emit(ev.FileFailed(member.nick, transfer.name, str(exc)))
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    # --- служебное ------------------------------------------------------------

    async def _send_to_session(self, session: Session, envelope: Envelope) -> None:
        try:
            await session.send(envelope.encode())
        except (LinkClosed, SessionError):
            pass  # разрыв заметит читающая задача и сообщит один раз

    def _connection_by_nick(self, nick: str) -> Connection | None:
        for conn in self._connections.values():
            if conn.nick == nick:
                return conn
        return None

    def _drop_transfers(self, public: bytes) -> None:
        for transfer_id, (owner, transfer) in list(self._incoming.items()):
            if owner == public:
                transfer.decline()
                self._incoming.pop(transfer_id, None)

    async def _emit(self, event: ev.Event) -> None:
        await self.events.put(event)

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
