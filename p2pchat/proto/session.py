"""Защищённая сессия поверх произвольного ``Link``.

Здесь три вещи, которых не было в криптоядре.

**Привязка заголовка.** Тип кадра и счётчик сообщений идут в associated data.
Подмена типа (выдать данные за служебный кадр) или пропуск сообщения ломают
проверку тега.

**Ротация свежим DH.** ``CipherState.rekey()`` из спецификации Noise даёт только
forward secrecy. Здесь стороны обмениваются новыми эфемерными ключами и
подмешивают общий секрет в цепочку ``ck``, унаследованную от хендшейка. Это даёт
post-compromise security: противник, укравший ключи, теряет доступ после
ближайшей ротации, если не перехватил и её.

**Разрешение гонок.** Ротацию инициирует только та сторона, что начинала
хендшейк. Второй стороне при достижении порогов остаётся послать
``REKEY_REQUEST``. Иначе одновременный запуск с двух сторон дал бы два разных
набора ключей.

Порядок смены ключей опирается на упорядоченность канала::

    A: шлёт REKEY_INIT (старым ключом), перестаёт слать данные
    B: получает, отвечает REKEY_ACK (ещё старым), затем переключается
    A: получает ACK, переключается, возобновляет отправку

Данные, отправленные B сразу после переключения, придут строго после ACK,
поэтому A к этому моменту уже с новым ключом.
"""

from __future__ import annotations

import asyncio
import time

from ..crypto import primitives as p
from ..crypto.identity import Identity
from ..crypto.noise import CipherState
from ..crypto.noise_xx import HandshakeState
from ..crypto.sas import sas_code
from ..net.link import Link, LinkClosed

KIND_DATA = 1
KIND_REKEY_INIT = 2
KIND_REKEY_ACK = 3
KIND_REKEY_REQUEST = 4

PROTOCOL_VERSION = b"p2pchat/1"

REKEY_AFTER_MESSAGES = 1000
REKEY_AFTER_SECONDS = 900.0
REKEY_TIMEOUT = 20.0
HANDSHAKE_TIMEOUT = 30.0

MAX_PLAINTEXT = 64 * 1024 - 1 - p.TAGLEN

# Ограничение очереди входящих даёт backpressure: читающая задача блокируется
# на переполнении, TCP-окно закрывается, и пир перестаёт слать. Неограниченная
# очередь означала бы, что достаточно быстрый отправитель съедает нашу память.
INBOX_LIMIT = 256


class SessionError(Exception):
    """Нарушение протокола сессии."""


def build_prologue(mode: str = "direct", group_id: bytes = b"") -> bytes:
    """Контекст, привязываемый к хендшейку.

    Prologue входит в хеш стенограммы, поэтому стороны с разной версией
    протокола или разной группой не сойдутся — и узнают об этом на хендшейке,
    а не посреди переписки.
    """
    return PROTOCOL_VERSION + b"|" + mode.encode() + b"|" + group_id


class Session:
    """Одно защищённое соединение с одним пиром."""

    def __init__(
        self,
        link: Link,
        handshake: HandshakeState,
        *,
        initiator: bool,
        peer_payload: bytes,
    ) -> None:
        self._link = link
        self._initiator = initiator
        self._remote_static = handshake.remote_static
        self._handshake_hash = handshake.handshake_hash
        self._ck = handshake.chaining_key
        self._send_cs, self._recv_cs = handshake.split()
        self.peer_payload = peer_payload

        self._send_lock = asyncio.Lock()
        self._inbox: asyncio.Queue = asyncio.Queue(maxsize=INBOX_LIMIT)
        self._failure: BaseException | None = None
        self._rekey_done = asyncio.Event()
        self._pending_ephemeral: p.KeyPair | None = None
        self._rekey_requested = False
        self._messages_since_rekey = 0
        self._last_rekey = time.monotonic()
        self._rekey_count = 0
        self._closed = False
        self._reader_task = asyncio.create_task(self._read_loop())

    # --- установка соединения -------------------------------------------------

    @classmethod
    async def initiate(
        cls, link: Link, identity: Identity, *, prologue: bytes = b"", payload: bytes = b""
    ) -> "Session":
        hs = HandshakeState(initiator=True, static=identity.keypair, prologue=prologue)
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            await link.send_frame(hs.write_message())
            peer_payload = hs.read_message(await link.recv_frame())
            await link.send_frame(hs.write_message(payload))
        return cls(link, hs, initiator=True, peer_payload=peer_payload)

    @classmethod
    async def accept(
        cls, link: Link, identity: Identity, *, prologue: bytes = b"", payload: bytes = b""
    ) -> "Session":
        hs = HandshakeState(initiator=False, static=identity.keypair, prologue=prologue)
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            hs.read_message(await link.recv_frame())
            await link.send_frame(hs.write_message(payload))
            peer_payload = hs.read_message(await link.recv_frame())
        return cls(link, hs, initiator=False, peer_payload=peer_payload)

    # --- свойства -------------------------------------------------------------

    @property
    def remote_static(self) -> bytes:
        """Статический ключ пира. Сам по себе НЕ доказывает, кто это, — до
        сверки SAS или совпадения с записью в списке известных пиров."""
        return self._remote_static

    @property
    def sas(self) -> str:
        return sas_code(self._handshake_hash)

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def link_description(self) -> str:
        """Как выглядит канал: для TCP — фактический адрес пира."""
        return self._link.description

    @property
    def rekey_count(self) -> int:
        """Сколько раз ключи сессии сменились свежим DH."""
        return self._rekey_count

    # --- обмен данными --------------------------------------------------------

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise LinkClosed("сессия закрыта")
        if len(data) > MAX_PLAINTEXT:
            raise SessionError(f"сообщение длиннее {MAX_PLAINTEXT} байт")
        if self._should_rekey():
            await self.rekey()
        async with self._send_lock:
            await self._send_locked(KIND_DATA, data)
        self._messages_since_rekey += 1

    async def receive(self) -> bytes:
        """Ждёт следующее сообщение.

        Ошибка канала «липкая»: она поднимается при каждом последующем вызове,
        а не один раз. Иначе второй ``receive()`` после разрыва повис бы навсегда.
        """
        if self._failure is not None and self._inbox.empty():
            raise self._failure
        item = await self._inbox.get()
        if isinstance(item, BaseException):
            self._failure = item
            raise item
        return item

    def __aiter__(self) -> "Session":
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.receive()
        except LinkClosed as exc:
            raise StopAsyncIteration from exc

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._failure is None:
            self._failure = LinkClosed("сессия закрыта")
        self._reader_task.cancel()
        try:
            self._inbox.put_nowait(self._failure)
        except asyncio.QueueFull:
            pass
        await self._link.close()

    # --- ротация ключей -------------------------------------------------------

    async def rekey(self) -> None:
        """Свежий DH-обмен. Вызывается только инициатором сессии."""
        if not self._initiator:
            async with self._send_lock:
                await self._send_locked(KIND_REKEY_REQUEST, b"")
            return

        async with self._send_lock:
            self._pending_ephemeral = p.KeyPair.generate()
            self._rekey_done.clear()
            await self._send_locked(KIND_REKEY_INIT, self._pending_ephemeral.public)
            try:
                await asyncio.wait_for(self._rekey_done.wait(), REKEY_TIMEOUT)
            except asyncio.TimeoutError as exc:
                await self.close()
                raise SessionError("пир не подтвердил ротацию ключей") from exc

    def _should_rekey(self) -> bool:
        if not self._initiator:
            return False
        return (
            self._rekey_requested
            or self._messages_since_rekey >= REKEY_AFTER_MESSAGES
            or time.monotonic() - self._last_rekey >= REKEY_AFTER_SECONDS
        )

    def _apply_rekey(self, shared: bytes) -> None:
        """Продолжает цепочку ``ck`` и выдаёт обеим сторонам новые ключи."""
        self._ck, k_initiator, k_responder = p.hkdf(self._ck, shared, 3)
        if self._initiator:
            self._send_cs = CipherState(k_initiator)
            self._recv_cs = CipherState(k_responder)
        else:
            self._send_cs = CipherState(k_responder)
            self._recv_cs = CipherState(k_initiator)
        self._messages_since_rekey = 0
        self._rekey_requested = False
        self._last_rekey = time.monotonic()
        self._rekey_count += 1

    # --- внутреннее -----------------------------------------------------------

    async def _send_locked(self, kind: int, payload: bytes) -> None:
        header = bytes([kind])
        ad = header + self._send_cs.n.to_bytes(8, "big")
        await self._link.send_frame(header + self._send_cs.encrypt_with_ad(ad, payload))

    async def _read_loop(self) -> None:
        try:
            while True:
                frame = await self._link.recv_frame()
                if len(frame) < 1 + p.TAGLEN:
                    raise SessionError("кадр короче минимально возможного")
                kind = frame[0]
                ad = frame[:1] + self._recv_cs.n.to_bytes(8, "big")
                payload = self._recv_cs.decrypt_with_ad(ad, frame[1:])
                await self._dispatch(kind, payload)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 — исключение уходит в receive()
            self._closed = True
            failure = exc if isinstance(exc, Exception) else LinkClosed(str(exc))
            self._failure = failure
            # put_nowait: очередь может быть полна, а ждать место уже незачем —
            # флаг _failure всё равно разбудит получателя.
            try:
                self._inbox.put_nowait(failure)
            except asyncio.QueueFull:
                pass

    async def _dispatch(self, kind: int, payload: bytes) -> None:
        if kind == KIND_DATA:
            await self._inbox.put(payload)
            return

        if kind == KIND_REKEY_INIT:
            if self._initiator:
                raise SessionError("инициатор получил REKEY_INIT — так быть не должно")
            if len(payload) != p.DHLEN:
                raise SessionError("некорректный эфемерный ключ в REKEY_INIT")
            ours = p.KeyPair.generate()
            shared = p.dh(ours, payload)
            async with self._send_lock:
                await self._send_locked(KIND_REKEY_ACK, ours.public)
                self._apply_rekey(shared)
            return

        if kind == KIND_REKEY_ACK:
            if not self._initiator or self._pending_ephemeral is None:
                raise SessionError("неожиданный REKEY_ACK")
            if len(payload) != p.DHLEN:
                raise SessionError("некорректный эфемерный ключ в REKEY_ACK")
            shared = p.dh(self._pending_ephemeral, payload)
            self._pending_ephemeral = None
            self._apply_rekey(shared)
            self._rekey_done.set()
            return

        if kind == KIND_REKEY_REQUEST:
            # Ротацию запускаем не здесь: инициатор может держать блокировку
            # отправки. Ставим флаг — он сработает на ближайшей отправке.
            self._rekey_requested = True
            return

        raise SessionError(f"неизвестный тип кадра: {kind}")
