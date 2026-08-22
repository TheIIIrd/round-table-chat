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
from ..net.discovery import Discovery
from ..net.link import LinkClosed
from ..net.tcp import TcpLink, serve
from . import events as ev
from .envelope import (
    TYPE_ADDRESS,
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
FIRST_RECONNECT_DELAY = 0.25
MAX_DIAL_BACKOFF = 2.0  # пока кого-то не хватает, дольше двух секунд не ждём
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
        discover_lan: bool = False,
    ) -> None:
        self.identity = identity
        self.nickname = nickname[:MAX_NICK_LEN]
        self.roster = roster
        self.trust = trust
        self.download_dir = Path(download_dir)
        self.listen = listen
        self.discover_lan = discover_lan

        self.events: asyncio.Queue = asyncio.Queue()
        self.clock = LamportClock()
        self._connections: dict[bytes, Connection] = {}
        self._incoming: dict[bytes, tuple[bytes, IncomingTransfer]] = {}
        self._outgoing: dict[bytes, OutgoingTransfer] = {}
        self._tasks: set[asyncio.Task] = set()
        self._server: asyncio.Server | None = None
        self._discovery: Discovery | None = None
        self._discovered: dict[bytes, tuple[str, int]] = {}
        self._dialing: set[bytes] = set()
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
        if self.discover_lan and self.roster is not None and self.listen is not None:
            self._discovery = Discovery(
                group_id=self.group_id,
                public=self.identity.public,
                nick=self.nickname,
                port=self.listen[1],
                on_peer=self._on_discovered,
                on_error=self._on_discovery_error,
            )
            try:
                await self._discovery.start()
                await self._emit(ev.Notice("обнаружение в локальной сети включено"))
            except OSError as exc:
                self._discovery = None
                await self._emit(ev.Notice(f"обнаружение недоступно: {exc}"))

    async def stop(self) -> None:
        self._running = False
        for task in list(self._tasks):
            task.cancel()
        for conn in list(self._connections.values()):
            conn.reader.cancel()
            await conn.session.close()
        self._connections.clear()
        if self._discovery is not None:
            await self._discovery.stop()
            self._discovery = None
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
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            await self._emit(ev.Notice(f"не удалось соединиться с {host}:{port}: {exc}"))
            return
        self.trust.remember_address(session.remote_static, host, port)
        await self._register(session)

    def _candidate_address(self, member: Member) -> tuple[str, int] | None:
        """Откуда узнаём, куда звонить: три источника по убыванию свежести.

        Бикон из локальной сети — самый свежий; последний удавшийся адрес
        переживает смену IP; адрес из ростера — то, что записали руками.
        """
        discovered = self._discovered.get(member.public)
        if discovered is not None:
            return discovered
        record = self.trust.by_key(member.public)
        if record is not None and record.endpoint is not None:
            return record.endpoint
        return member.address

    def _should_dial(self, member: Member) -> bool:
        if self._candidate_address(member) is None:
            return False
        if self.listen is None:
            return True
        return self.identity.public < member.public

    def _on_discovery_error(self, message: str) -> None:
        """Молчащее обнаружение хуже отсутствующего — говорим вслух один раз."""
        self.events.put_nowait(
            ev.Notice(
                f"обнаружение в сети не работает ({message}); "
                "укажите адреса в ростере или подключитесь через /connect"
            )
        )

    def _on_discovered(self, public: bytes, host: str, port: int, _nick: str) -> None:
        if self.roster is None or self.roster.by_key(public) is None:
            return  # бикон не из нашей группы или от неизвестного ключа
        if self._discovered.get(public) == (host, port):
            return
        self._discovered[public] = (host, port)

    async def _dial_loop(self) -> None:
        """Дозванивается до тех, кому положено звонить нам.

        Пока кто-то из группы не на связи, пауза растёт от четверти секунды до
        двух — пиры поднимаются вразнобой, и ждать дольше только потому, что
        сосед запустился на мгновение позже, незачем. Когда все собрались,
        интервал уходит на пять секунд и перестаёт шуметь.
        """
        if self.roster is None:
            return
        delay = FIRST_RECONNECT_DELAY
        while self._running:
            expected = [
                member
                for member in self.roster.others(self.identity.public)
                if self._should_dial(member)
            ]
            for member in expected:
                if member.public in self._connections or member.public in self._dialing:
                    continue  # звонок уже в пути: второй создал бы дубликат
                candidate = self._candidate_address(member)
                if candidate is None:
                    continue
                host, port = candidate
                self._dialing.add(member.public)
                try:
                    link = await TcpLink.connect(host, port)
                    session = await Session.initiate(
                        link,
                        self.identity,
                        prologue=self.prologue,
                        payload=self.nickname.encode("utf-8"),
                    )
                # pylint: disable-next=broad-exception-caught
                except Exception:
                    continue  # пир ещё не поднялся — попробуем на следующем круге
                finally:
                    self._dialing.discard(member.public)
                self.trust.remember_address(member.public, host, port)
                await self._register(session)

            everyone_here = all(member.public in self._connections for member in expected)
            delay = RECONNECT_DELAY if everyone_here else min(delay * 2, MAX_DIAL_BACKOFF)
            await asyncio.sleep(delay)

    async def _on_inbound(self, link: TcpLink) -> None:
        try:
            session = await Session.accept(
                link,
                self.identity,
                prologue=self.prologue,
                payload=self.nickname.encode("utf-8"),
            )
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # Кто угодно может постучаться в открытый порт; неудачный хендшейк
            # не повод ронять слушающий сокет.
            await self._emit(ev.Notice(f"входящее соединение отклонено: {exc}"))
            return
        await self._register(session)
        conn = self._connections.get(session.remote_static)
        if conn is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await conn.reader

    # --- регистрация и проверка доверия ---------------------------------------

    async def _register(self, session: Session) -> None:
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
        await self._send_to_session(
            session, make(TYPE_PRESENCE, self.clock, self.nickname.encode())
        )
        if self.listen is not None:
            # Сообщаем свой порт внутри уже зашифрованного канала: тот, кто с
            # нами хоть раз соединился, переживёт смену нашего IP. Хост не шлём —
            # пир и так видит, откуда мы пришли, а мы своего внешнего адреса
            # обычно не знаем (за NAT в self.listen лежит 0.0.0.0).
            await self._send_to_session(
                session, make(TYPE_ADDRESS, self.clock, self.listen[1].to_bytes(2, "big"))
            )

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
        """Читает сообщения пира до обрыва.

        В конце убирает из таблицы ИМЕННО СВОЮ сессию. Раньше запись удалялась
        по ключу пира: при гонке дубликатов закрытие лишнего соединения выносило
        из таблицы живое, и участник пропадал из чата, продолжая быть на связи.
        """
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
            raise  # отмена задачи не должна попасть в общий обработчик ниже
        except LinkClosed as exc:
            reason = str(exc)
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            reason = f"ошибка: {exc}"
        finally:
            current = self._connections.get(member.public)
            mine = current is not None and current.session is session
            if mine:
                self._connections.pop(member.public, None)
            await session.close()
            if mine:
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

        if envelope.type == TYPE_ADDRESS:
            self._remember_announced_address(member, session, envelope.body)
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

    def _remember_announced_address(self, member: Member, session: Session, body: bytes) -> None:
        """Записывает адрес, по которому этот пир будет доступен впредь.

        Порт пир называет сам, а хост мы берём из фактического сокета: свой
        внешний адрес пир обычно не знает, зато мы его видим.
        """
        if len(body) != 2:
            return
        port = int.from_bytes(body, "big")
        if not 1 <= port <= 65535:
            return
        observed = self._observed_host(session)
        if observed:
            self.trust.remember_address(member.public, observed, port)

    @staticmethod
    def _observed_host(session: Session) -> str | None:
        description = getattr(session, "link_description", "")
        host, _, _port = description.rpartition(":")
        return host or None

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
