"""Прикладной слой: что означают байты, которые доставила сеть.

Соединения, доверие и обнаружение живут в ``network.py``. Здесь остаётся то,
ради чего всё затевалось: конверты, текст, передача файлов и поток событий для
интерфейса.

Про очередь событий. Она **ограничена**, и это не формальность: в сессии стоит
предел на входящие сообщения, но меш вычитывает сессию непрерывно и складывает
всё сюда. Пока очередь была неограниченной, ограничение уровнем ниже не значило
ничего — давление просто переезжало наверх, где его никто не сдерживал. Теперь
при переполнении читающая задача притормаживает, TCP-окно закрывается, и
отправитель замедляется сам.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from ..crypto.identity import Identity
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
    make,
)
from .files import (
    TRANSFER_ID_LEN,
    IncomingTransfer,
    OutgoingTransfer,
    TransferError,
    decode_id,
)
from .network import PeerNetwork
from .roster import Member, Roster
from .trust import TrustStore

EVENT_QUEUE_LIMIT = 512

# Сколько предложений файлов от одного участника держим одновременно и сколько
# ждём ответа. Без предела поток предложений — это и рост памяти, и заваленный
# уведомлениями чат.
MAX_PENDING_OFFERS_PER_PEER = 3
MAX_OUTGOING_OFFERS_PER_PEER = 3
OFFER_TTL = 300.0
TRANSFER_IDLE_TIMEOUT = 120.0
SWEEP_INTERVAL = 10.0

# Пауза между кусками файла. Куски идут в ту же сессию, что и реплики, поэтому
# сплошной поток делает разговор с этим участником односторонней трубой до конца
# передачи. Короткая пауза каждые несколько кусков даёт тексту пройти между
# ними; на 64 МиБ это добавляет меньше секунды.
CHUNKS_BETWEEN_PAUSES = 16
CHUNK_PAUSE = 0.005


class _Incoming:
    """Принимаемая передача плюс отметка о последней активности."""

    __slots__ = ("owner", "transfer", "touched")

    def __init__(self, owner: bytes, transfer: IncomingTransfer, touched: float) -> None:
        self.owner = owner
        self.transfer = transfer
        self.touched = touched


class _Outgoing:
    """Предложенная передача: кому предложили и когда.

    Раньше здесь лежал голый ``OutgoingTransfer`` без адресата и времени,
    поэтому предложение, на которое никто не ответил, оставалось в памяти
    навсегда — уборщик был написан только для входящих.
    """

    __slots__ = ("target", "nick", "transfer", "touched")

    def __init__(self, target: bytes, nick: str, transfer: OutgoingTransfer, touched: float):
        self.target = target
        self.nick = nick
        self.transfer = transfer
        self.touched = touched


class Mesh:
    """Обмен сообщениями и файлами поверх сети участников."""

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
        self.download_dir = Path(download_dir)
        self.events: asyncio.Queue = asyncio.Queue(maxsize=EVENT_QUEUE_LIMIT)

        self.network = PeerNetwork(
            identity,
            nickname=nickname,
            roster=roster,
            trust=trust,
            listen=listen,
            discover_lan=discover_lan,
            emit=self._emit,
            on_message=self._on_message,
            on_ready=self._greet,
        )

        self._incoming: dict[bytes, _Incoming] = {}
        self._outgoing: dict[bytes, _Outgoing] = {}
        self._tasks: set[asyncio.Task] = set()
        self._janitor: asyncio.Task | None = None

    # Проброшенных свойств здесь намеренно нет. Они были — nickname, roster,
    # trust, peers, listen — и размывали границу, которую разделение слоёв
    # только что провело: по коду становилось не видно, кто за что отвечает.
    # Всё, что относится к соединениям, спрашивается у mesh.network явно.

    # --- жизненный цикл ---------------------------------------------------------

    async def start(self) -> None:
        await self.network.start()
        self._janitor = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        if self._janitor is not None:
            self._janitor.cancel()
            self._janitor = None
        for task in list(self._tasks):
            task.cancel()
        for entry in list(self._incoming.values()):
            entry.transfer.decline()
        self._incoming.clear()
        self._outgoing.clear()
        await self.network.stop()

    # --- отправка ---------------------------------------------------------------

    async def broadcast(self, text: str) -> None:
        await self.network.broadcast(make(TYPE_TEXT, text.encode("utf-8")).encode())

    async def send_text(self, nick: str, text: str) -> bool:
        return await self.network.send_to_nick(
            nick, make(TYPE_TEXT, text.encode("utf-8")).encode()
        )

    async def _greet(self, member: Member) -> None:
        """Что говорим сразу после установки соединения."""
        await self.network.send(
            member.public, make(TYPE_PRESENCE, self.network.nickname.encode()).encode()
        )
        if self.network.listen is not None:
            # Сообщаем свой порт внутри уже зашифрованного канала: тот, кто с
            # нами соединился, переживёт смену нашего IP.
            port = self.network.listen[1].to_bytes(2, "big")
            await self.network.send(member.public, make(TYPE_ADDRESS, port).encode())

    # --- файлы -------------------------------------------------------------------

    async def offer_file(self, nick: str, path: str | Path) -> None:
        member = self.network.member_by_nick(nick)
        if member is None:
            await self._emit(ev.Notice(f"участник {nick} не на связи"))
            return
        waiting = sum(1 for item in self._outgoing.values() if item.target == member.public)
        if waiting >= MAX_OUTGOING_OFFERS_PER_PEER:
            await self._emit(
                ev.Notice(f"{nick} ещё не ответил на предыдущие предложения — подождите")
            )
            return

        try:
            # Построение считает BLAKE2b по всему файлу. В цикле событий это
            # замораживает чат на всё время хеширования, поэтому — в поток.
            transfer = await asyncio.to_thread(OutgoingTransfer, path=Path(path))
        except TransferError as exc:
            await self._emit(ev.Notice(str(exc)))
            return
        self._outgoing[transfer.transfer_id] = _Outgoing(
            target=member.public, nick=nick, transfer=transfer, touched=time.monotonic()
        )
        await self.network.send(
            member.public, make(TYPE_FILE_OFFER, transfer.offer_body()).encode()
        )
        await self._emit(ev.Notice(f"предложил {nick} файл «{transfer.name}», жду ответа"))

    async def respond_to_offer(self, short_id: str, accept: bool) -> None:
        """Принимает или отклоняет предложение по началу идентификатора.

        Пустая строка не годится: ``"abc".startswith("")`` истинно, поэтому
        `/accept` без аргумента принимал первое попавшееся предложение — ровно
        тот файл, который принимать не собирались. Неоднозначный префикс тоже
        отклоняется: угаданный не тот файл хуже переспроса.
        """
        short_id = short_id.strip().lower()
        if not short_id:
            await self._emit(ev.Notice("укажите идентификатор: /accept <id> или /decline <id>"))
            return

        matches = [
            transfer_id for transfer_id in self._incoming if transfer_id.hex().startswith(short_id)
        ]
        if not matches:
            await self._emit(ev.Notice(f"нет предложения файла с идентификатором {short_id}"))
            return
        if len(matches) > 1:
            options = ", ".join(item.hex()[:8] for item in matches)
            await self._emit(ev.Notice(f"под «{short_id}» подходит несколько: {options}"))
            return

        await self._respond(matches[0], accept)

    async def _respond(self, transfer_id: bytes, accept: bool) -> None:
        entry = self._incoming[transfer_id]
        if not self.network.is_connected(entry.owner):
            entry.transfer.decline()
            self._incoming.pop(transfer_id, None)
            return

        if accept:
            try:
                entry.transfer.accept()
            except OSError as exc:
                # Каталог загрузок может быть недоступен: нет прав, кончилось
                # место, на его месте файл. Это не повод ронять весь чат.
                self._incoming.pop(transfer_id, None)
                await self.network.send(
                    entry.owner, make(TYPE_FILE_DECLINE, transfer_id).encode()
                )
                await self._emit(
                    ev.FileFailed("", entry.transfer.name, f"не удалось начать приём: {exc}")
                )
                return
            entry.touched = time.monotonic()
            kind = TYPE_FILE_ACCEPT
        else:
            entry.transfer.decline()
            self._incoming.pop(transfer_id, None)
            kind = TYPE_FILE_DECLINE
        await self.network.send(entry.owner, make(kind, transfer_id).encode())

    async def _push_file(self, member: Member, transfer: OutgoingTransfer) -> None:
        try:
            for index, chunk in enumerate(transfer.chunks()):
                sent = await self.network.send(
                    member.public, make(TYPE_FILE_CHUNK, chunk).encode()
                )
                if not sent:
                    raise TransferError("соединение потеряно")
                if index % CHUNKS_BETWEEN_PAUSES == CHUNKS_BETWEEN_PAUSES - 1:
                    await asyncio.sleep(CHUNK_PAUSE)
            await self.network.send(
                member.public, make(TYPE_FILE_DONE, transfer.transfer_id).encode()
            )
            await self._emit(ev.FileSent(member.nick, transfer.name))
        except (TransferError, OSError) as exc:
            await self._emit(ev.FileFailed(member.nick, transfer.name, str(exc)))
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    # --- приём --------------------------------------------------------------------

    async def _on_message(self, member: Member, raw: bytes) -> None:
        try:
            envelope = Envelope.decode(raw)
        except EnvelopeError as exc:
            await self._emit(ev.Notice(f"мусор от {member.nick}: {exc}"))
            return

        if envelope.type == TYPE_TEXT:
            await self._emit(
                ev.TextMessage(
                    nick=member.nick,
                    public=member.public,
                    text=envelope.body.decode("utf-8", errors="replace"),
                    is_bot=member.is_bot,
                )
            )
            return

        if envelope.type == TYPE_PRESENCE:
            return

        if envelope.type == TYPE_ADDRESS:
            if len(envelope.body) == 2:
                self.network.remember_peer_port(member, int.from_bytes(envelope.body, "big"))
            return

        try:
            await self._handle_file(member, envelope)
        except TransferError as exc:
            await self._emit(ev.FileFailed(member.nick, "", str(exc)))

    async def _handle_file(self, member: Member, envelope: Envelope) -> None:
        if envelope.type == TYPE_FILE_OFFER:
            await self._on_offer(member, envelope.body)

        elif envelope.type == TYPE_FILE_ACCEPT:
            outgoing = self._outgoing.get(decode_id(envelope.body))
            if outgoing is not None and outgoing.target == member.public:
                outgoing.touched = time.monotonic()
                self._spawn(self._push_file(member, outgoing.transfer))

        elif envelope.type == TYPE_FILE_DECLINE:
            transfer_id = decode_id(envelope.body)
            outgoing = self._outgoing.get(transfer_id)
            if outgoing is not None and outgoing.target == member.public:
                self._outgoing.pop(transfer_id, None)
                await self._emit(
                    ev.FileFailed(member.nick, outgoing.transfer.name, "получатель отказался")
                )

        elif envelope.type == TYPE_FILE_CHUNK:
            transfer_id = envelope.body[:TRANSFER_ID_LEN]
            entry = self._incoming.get(transfer_id)
            if entry is None:
                return
            if entry.owner != member.public:
                raise TransferError("кусок пришёл не от того участника")
            try:
                entry.transfer.add_chunk(envelope.body)
            except TransferError as exc:
                # Битую передачу закрываем сразу, а не оставляем уборщику:
                # продолжать её всё равно нельзя, а .part занимает место.
                entry.transfer.decline()
                self._incoming.pop(transfer_id, None)
                await self._emit(ev.FileFailed(member.nick, entry.transfer.name, str(exc)))
                return
            entry.touched = time.monotonic()

        elif envelope.type == TYPE_FILE_DONE:
            await self._finish_incoming(member, decode_id(envelope.body))

    async def _finish_incoming(self, member: Member, transfer_id: bytes) -> None:
        entry = self._incoming.get(transfer_id)
        if entry is None:
            return
        if entry.owner != member.public:
            # Проверка ДО снятия записи: иначе чужое сообщение выбивало бы
            # передачу из списка вместе с доступом к её временному файлу.
            raise TransferError("завершение пришло не от того участника")
        self._incoming.pop(transfer_id, None)
        try:
            # finish() перечитывает и хеширует весь временный файл — тоже в поток.
            path = await asyncio.to_thread(entry.transfer.finish)
        except TransferError as exc:
            await self._emit(ev.FileFailed(member.nick, entry.transfer.name, str(exc)))
            return
        await self._emit(ev.FileFinished(member.nick, entry.transfer.name, path))

    async def _on_offer(self, member: Member, body: bytes) -> None:
        transfer = IncomingTransfer.from_offer(body, self.download_dir)

        pending = sum(1 for entry in self._incoming.values() if entry.owner == member.public)
        if pending >= MAX_PENDING_OFFERS_PER_PEER:
            # Отказываем вслух: молчание оставило бы отправителя ждать вечно.
            await self.network.send(
                member.public, make(TYPE_FILE_DECLINE, transfer.transfer_id).encode()
            )
            await self._emit(
                ev.Notice(f"{member.nick} шлёт слишком много предложений файлов — отклонил")
            )
            return

        self._incoming[transfer.transfer_id] = _Incoming(
            owner=member.public, transfer=transfer, touched=time.monotonic()
        )
        await self._emit(
            ev.FileOffered(
                nick=member.nick,
                transfer_id=transfer.transfer_id.hex()[:8],
                name=transfer.name,
                size=transfer.size,
            )
        )

    # --- уборка ----------------------------------------------------------------------

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL)
            await self.sweep(time.monotonic())

    async def sweep(self, now: float) -> None:
        """Убирает зависшее с обеих сторон.

        Принятая, но не завершённая передача иначе навсегда оставляла бы файл
        `.part` на диске, а предложение, на которое не ответили, — запись в
        памяти отправителя.
        """
        await self._sweep_outgoing(now)
        for transfer_id, entry in list(self._incoming.items()):
            active = entry.transfer.is_active
            limit = TRANSFER_IDLE_TIMEOUT if active else OFFER_TTL
            gone = not self.network.is_connected(entry.owner)
            expired = now - entry.touched > limit
            if not (gone or expired):
                continue

            entry.transfer.decline()
            self._incoming.pop(transfer_id, None)
            if expired and not gone and active:
                await self._emit(
                    ev.FileFailed("", entry.transfer.name, "передача заброшена — отменена")
                )

    async def _sweep_outgoing(self, now: float) -> None:
        for transfer_id, item in list(self._outgoing.items()):
            gone = not self.network.is_connected(item.target)
            expired = now - item.touched > OFFER_TTL
            if not (gone or expired):
                continue
            self._outgoing.pop(transfer_id, None)
            reason = "участник отключился" if gone else "никто не ответил"
            await self._emit(ev.FileFailed(item.nick, item.transfer.name, reason))

    async def _emit(self, event: ev.Event) -> None:
        await self.events.put(event)

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
