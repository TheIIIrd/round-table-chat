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
from .commands import registry
from .registry import Context, Registry

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
        commands: Registry | None = None,
    ) -> None:
        self.commands = commands or registry
        self.mesh = Mesh(
            identity,
            nickname=nickname,
            roster=roster,
            trust=TrustStore.load(trust_path),
            # Каталог задан, но бот не принимает файлы — см. _handle.
            download_dir=Path("/nonexistent"),
            listen=listen,
        )

    async def run(self) -> None:
        await self.mesh.start()
        log.info("бот %s запущен, команды: %s", self.mesh.nickname, self.commands.names)
        try:
            while True:
                await self._handle(await self.mesh.events.get())
        except asyncio.CancelledError:
            raise
        finally:
            await self.mesh.stop()

    async def _handle(self, event: ev.Event) -> None:
        if isinstance(event, ev.TextMessage):
            if event.is_bot:
                return  # защита от переписки ботов между собой
            reply = await self.commands.dispatch(
                Context(nick=event.nick, public=event.public), event.text
            )
            if reply:
                await self.mesh.broadcast(reply)
            return

        if isinstance(event, ev.FileOffered):
            await self.mesh.respond_to_offer(event.transfer_id, accept=False)
            log.info("отклонил файл «%s» от %s", event.name, event.nick)
            return

        if isinstance(event, (ev.PeerConnected, ev.PeerDisconnected, ev.Alert, ev.Notice)):
            log.info("%s", event.render().replace("\n", " "))
