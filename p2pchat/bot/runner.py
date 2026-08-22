"""Бот как полноправный участник меша.

Никакой отдельной криптографии у бота нет: это тот же ``Mesh``, только вместо
клавиатуры у него разбор команд, а вместо экрана — журнал. Его ключ так же
лежит в ростере и так же участвует в вычислении идентификатора группы, поэтому
остальные видят его как обычного участника с пометкой «бот».

Ограничения, встроенные намеренно:

* бот не реагирует на сообщения других ботов и на свои собственные — иначе
  два бота устроят бесконечную переписку;
* бот никогда не принимает файлы;
* бот не выполняет ничего, кроме зарегистрированных команд.

Про ключ бота: он работает без человека, значит пассфразу вводят один раз при
старте (тогда автоперезапуск невозможен) либо ключ доступен процессу
(тогда компрометация хоста бота = чтение всей переписки группы, ведь бот —
полноценный участник меша). Выбор осознанный, он делается флагом при запуске.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..crypto.identity import Identity
from ..proto import events as ev
from ..proto.mesh import Mesh
from ..proto.roster import Roster
from ..proto.trust import TrustStore
from ..games import build_host
from ..games.api import Action, Finish, Say, Whisper
from ..games.lobby import GameHost
from .commands import registry
from .registry import PREFIX, Context, Registry, TokenBucket

log = logging.getLogger("p2pchat.bot")


class Bot:
    def __init__(
        self,
        identity: Identity,
        *,
        nickname: str,
        roster: Roster,
        trust_path: Path,
        listen: tuple[str, int] | None,
        discover_lan: bool = False,
        commands: Registry | None = None,
        host: GameHost | None = None,
    ) -> None:
        self.commands = commands or registry
        self.host = host or build_host()
        self._buckets: dict[str, TokenBucket] = {}
        self.mesh = Mesh(
            identity,
            nickname=nickname,
            roster=roster,
            trust=TrustStore.load(trust_path),
            # Каталог задан, но бот не принимает файлы — см. _handle.
            download_dir=Path("/nonexistent"),
            listen=listen,
            discover_lan=discover_lan,
        )

    async def run(self) -> None:
        await self.mesh.start()
        log.info("бот %s запущен, команды: %s", self.mesh.nickname, self.commands.names)
        ticker = asyncio.create_task(self._tick_loop())
        try:
            while True:
                await self._handle(await self.mesh.events.get())
        except asyncio.CancelledError:
            raise
        finally:
            ticker.cancel()
            await self.mesh.stop()

    async def _tick_loop(self) -> None:
        """Раз в секунду двигаем таймауты партии: ходов и сбора игроков."""
        while True:
            await asyncio.sleep(1.0)
            await self._perform(self.host.tick())

    async def _handle(self, event: ev.Event) -> None:
        if isinstance(event, ev.TextMessage):
            if event.is_bot:
                return  # защита от переписки ботов между собой
            if await self._try_game(event):
                return
            reply = await self.commands.dispatch(
                Context(nick=event.nick, public=event.public), event.text
            )
            if reply:
                await self.mesh.broadcast(reply)
            return

        if isinstance(event, ev.PeerConnected):
            # Вернулся посреди партии — возвращаем его приватное состояние.
            await self._perform(self.host.on_peer_back(event.nick))

        if isinstance(event, ev.PeerDisconnected):
            await self._perform(self.host.on_peer_lost(event.nick))

        if isinstance(event, ev.FileOffered):
            await self.mesh.respond_to_offer(event.transfer_id, accept=False)
            log.info("отклонил файл «%s» от %s", event.name, event.nick)
            return

        if isinstance(event, (ev.PeerConnected, ev.PeerDisconnected, ev.Alert, ev.Notice)):
            log.info("%s", event.render().replace("\n", " "))

    async def _try_game(self, event: ev.TextMessage) -> bool:
        """Отдаёт ход игре, если команда её. Возвращает True, если обработано."""
        text = event.text.strip()
        if not text.startswith(PREFIX):
            return False
        verb, _, rest = text[len(PREFIX) :].strip().partition(" ")
        verb = verb.lower()
        if not self.host.owns(verb):
            return False

        bucket = self._buckets.setdefault(event.nick, TokenBucket())
        if not bucket.take():
            return True  # флуд гасим молча: ответ на флуд — тоже флуд

        await self._perform(self.host.dispatch(event.nick, verb, rest))
        return True

    async def _perform(self, actions: list[Action]) -> None:
        """Единственное место, где намерения игры превращаются в сообщения."""
        for action in actions:
            if isinstance(action, Say):
                await self.mesh.broadcast(action.text)
            elif isinstance(action, Whisper):
                await self.mesh.send_text(action.player, action.text)
            elif isinstance(action, Finish):
                await self.mesh.broadcast(action.summary)
