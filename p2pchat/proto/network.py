"""Сеть участников: кто с кем соединён и кого пускать.

Этот слой ничего не знает о сообщениях, файлах и играх. Он отвечает ровно за
три вещи: установить соединения с теми, кто в ростере, решить, кого пускать, и
доставить чужие байты наверх.

Разделение появилось не из любви к слоям. `Mesh` вырос в класс, который держал
соединения, доверие, обнаружение, файлы и события разом, и это дало о себе
знать: ограничение очереди в одном месте оказалось обойдено в другом, а уборка
передач расползлась по трём методам. Здесь граница проведена по естественному
шву — «доставить байты» против «что эти байты значат».

**Кто кому звонит.** Если оба пира одновременно подключатся друг к другу,
получатся две сессии вместо одной. Правило: звонит тот, чей публичный ключ
меньше. Ключи различны и упорядочены одинаково у обеих сторон, договариваться
не нужно. Исключение — участник без своего адреса: ему звонить некуда, поэтому
звонит он.

**Кого пускаем.** В групповом режиме ключ обязан быть в ростере — он там
зафиксирован, поэтому подмена ключа участника невозможна в принципе. В режиме
один на один ростера нет и работает TOFU: первый ключ запоминается,
несовпадение при следующем соединении — отказ.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ..crypto.identity import Identity, fingerprint
from ..net.discovery import Discovery
from ..net.link import LinkClosed
from ..net.tcp import TcpLink, serve
from . import events as ev
from .roster import Member, Roster
from .session import REKEY_TIMEOUT, Session, SessionError, build_prologue
from .trust import TrustDecision, TrustStore

RECONNECT_DELAY = 5.0
FIRST_RECONNECT_DELAY = 0.25
MAX_DIAL_BACKOFF = 2.0
# Таймаут отправки обязан быть БОЛЬШЕ таймаута ротации ключей, и это не вкусовое
# решение. Ротация запускается внутри session.send(), поэтому при меньшем
# значении внешний таймаут снимал бы отправку раньше, чем ротация успевала
# завершиться: сообщение терялось бы, а исправный пир отключался как «не
# принимающий данные». Величина выводится из session, а не пишется числом, чтобы
# правка там не разъехалась с этим слоем молча.
SEND_TIMEOUT = REKEY_TIMEOUT + 15.0
MAX_NICK_LEN = 32


@dataclass
class Connection:
    member: Member
    session: Session
    reader: asyncio.Task

    @property
    def nick(self) -> str:
        return self.member.nick


Emit = Callable[[ev.Event], Awaitable[None]]
OnMessage = Callable[[Member, bytes], Awaitable[None]]
OnReady = Callable[[Member], Awaitable[None]]


class PeerNetwork:
    """Соединения со всеми участниками группы."""

    def __init__(
        self,
        identity: Identity,
        *,
        nickname: str,
        roster: Roster | None,
        trust: TrustStore,
        listen: tuple[str, int] | None = None,
        discover_lan: bool = False,
        emit: Emit,
        on_message: OnMessage,
        on_ready: OnReady | None = None,
    ) -> None:
        self.identity = identity
        self.nickname = nickname[:MAX_NICK_LEN]
        self.roster = roster
        self.trust = trust
        self.listen = listen
        self.discover_lan = discover_lan

        self._emit = emit
        self._on_message = on_message
        self._on_ready = on_ready

        self._connections: dict[bytes, Connection] = {}
        self._dialing: set[bytes] = set()
        self._discovered: dict[bytes, tuple[str, int]] = {}
        self._tasks: set[asyncio.Task] = set()
        self._server: asyncio.Server | None = None
        self._discovery: Discovery | None = None
        self._running = False

    # --- свойства -------------------------------------------------------------

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

    def member_by_nick(self, nick: str) -> Member | None:
        for conn in self._connections.values():
            if conn.nick == nick:
                return conn.member
        return None

    def is_connected(self, public: bytes) -> bool:
        return public in self._connections

    # --- жизненный цикл -------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        if self.listen is not None:
            host, port = self.listen
            self._server = await serve(host, port, self._on_inbound)
            self.listen = (host, self._server.sockets[0].getsockname()[1])
            await self._emit(ev.Notice(f"слушаю {self.listen[0]}:{self.listen[1]}"))
        if self.roster is not None:
            self._spawn(self._dial_loop())
        await self._start_discovery()

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
            with contextlib.suppress(Exception):  # pylint: disable=broad-exception-caught
                await self._server.wait_closed()

    # --- отправка -------------------------------------------------------------

    async def send(self, public: bytes, payload: bytes) -> bool:
        conn = self._connections.get(public)
        if conn is None:
            return False
        return await self._deliver(conn, payload)

    async def send_to_nick(self, nick: str, payload: bytes) -> bool:
        for conn in list(self._connections.values()):
            if conn.nick == nick:
                return await self._deliver(conn, payload)
        return False

    async def broadcast(self, payload: bytes) -> None:
        """Рассылает всем параллельно.

        Последовательная рассылка означала бы, что один пир с забитым окном
        задерживает доставку всем остальным. Таймаут на пира тоже нужен: без
        него зависшее соединение подвешивало бы отправителя.
        """
        connections = list(self._connections.values())
        if not connections:
            return
        await asyncio.gather(
            *(self._deliver(conn, payload) for conn in connections), return_exceptions=True
        )

    async def _deliver(self, conn: Connection, payload: bytes) -> bool:
        try:
            await asyncio.wait_for(conn.session.send(payload), SEND_TIMEOUT)
            return True
        except (LinkClosed, SessionError):
            return False  # разрыв заметит читающая задача и сообщит один раз
        except asyncio.TimeoutError:
            await self._emit(ev.Notice(f"{conn.nick} не принимает данные — отключаю"))
            conn.reader.cancel()
            await conn.session.close()
            return False

    # --- исходящие соединения -------------------------------------------------

    async def connect_to(self, host: str, port: int) -> None:
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
        """Откуда узнаём, куда звонить: три источника по убыванию свежести."""
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

    async def _dial_loop(self) -> None:
        """Дозванивается до тех, кому положено звонить нам."""
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
                await self._dial_once(member)

            everyone_here = all(member.public in self._connections for member in expected)
            delay = RECONNECT_DELAY if everyone_here else min(delay * 2, MAX_DIAL_BACKOFF)
            await asyncio.sleep(delay)

    async def _dial_once(self, member: Member) -> None:
        if member.public in self._connections or member.public in self._dialing:
            return  # звонок уже в пути: второй создал бы дубликат
        candidate = self._candidate_address(member)
        if candidate is None:
            return
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
            return  # пир ещё не поднялся — попробуем на следующем круге
        finally:
            self._dialing.discard(member.public)
        self.trust.remember_address(member.public, host, port)
        await self._register(session)

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

    # --- регистрация и доверие -------------------------------------------------

    async def _register(self, session: Session) -> None:
        public = session.remote_static
        member = await self._authorize(session, public)
        if member is None:
            await session.close()
            return

        if public in self._connections:
            # Гонка: пир позвонил одновременно с нами.
            await self._emit(ev.Notice(f"повторное соединение с {member.nick} закрыто"))
            await session.close()
            return

        decision = self.trust.check(public, member.nick)
        if decision is TrustDecision.NEW:
            self.trust.remember(public, member.nick)

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
        if self._on_ready is not None:
            await self._on_ready(member)

    async def _authorize(self, session: Session, public: bytes) -> Member | None:
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

        if self.trust.check(public, nick) is TrustDecision.NICK_TAKEN:
            await self._emit(
                ev.Alert(
                    f"кто-то с другим ключом называется «{nick}» ({fingerprint(public)}). "
                    "Соединение отклонено. Если ваш собеседник переустановил чат — "
                    f"/forget {nick}"
                )
            )
            return None
        return Member(nick=nick, public=public)

    # --- приём -----------------------------------------------------------------

    async def _read_peer(self, member: Member, session: Session) -> None:
        """Читает сообщения пира до обрыва.

        В конце убирает из таблицы ИМЕННО СВОЮ сессию: при гонке дубликатов
        закрытие лишнего соединения не должно выносить живое.
        """
        reason = "соединение закрыто"
        try:
            while True:
                await self._on_message(member, await session.receive())
        except asyncio.CancelledError:
            raise
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
                await self._emit(ev.PeerDisconnected(member.nick, reason))

    # --- обнаружение в локальной сети -------------------------------------------

    async def _start_discovery(self) -> None:
        if not (self.discover_lan and self.roster is not None and self.listen is not None):
            return
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

    def _on_discovery_error(self, message: str) -> None:
        """Молчащее обнаружение хуже отсутствующего — говорим вслух один раз."""
        self._emit_soon(
            ev.Notice(
                f"обнаружение в сети не работает ({message}); "
                "укажите адреса в ростере или подключитесь через /connect"
            )
        )

    def _on_discovered(self, public: bytes, host: str, port: int, _nick: str) -> None:
        if self.roster is None or self.roster.by_key(public) is None:
            return  # бикон не из нашей группы или от неизвестного ключа
        self._discovered[public] = (host, port)

    def remember_peer_port(self, member: Member, port: int) -> None:
        """Записывает порт, о котором сообщил сам пир.

        Хост берём из фактического сокета: свой внешний адрес пир обычно не
        знает, зато мы его видим.
        """
        conn = self._connections.get(member.public)
        if conn is None or not 1 <= port <= 65535:
            return
        host, _, _tail = conn.session.link_description.rpartition(":")
        if host:
            self.trust.remember_address(member.public, host, port)

    # --- служебное ---------------------------------------------------------------

    def _emit_soon(self, event: ev.Event) -> None:
        self._spawn(self._emit(event))

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
