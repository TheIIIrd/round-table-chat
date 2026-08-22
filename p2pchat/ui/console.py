"""Консольный интерфейс.

Работает без внешних зависимостей: ввод читается из stdin в отдельном потоке
исполнителя, вывод идёт обычным ``print``. Если установлен ``prompt_toolkit``,
используется он — тогда строка ввода не рвётся приходящими сообщениями.

Оговорка: ветка с ``prompt_toolkit`` написана, но в этом окружении не
проверена — пакета там нет и поставить его неоткуда. Ветка без него
протестирована и работает.

Про сверку SAS. Вся стойкость к активному MITM держится на том, что человек
действительно сверит код голосом. Поэтому непроверенный собеседник помечается
в каждой строке восклицательным знаком, а не одним сообщением при подключении,
которое уедет вверх через десять реплик.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from ..format import sanitize
from ..proto import events as ev
from ..proto.mesh import Mesh
from ..proto.trust import TrustStore
from .style import Palette, build_palette

BANNER = """p2pchat — консольный P2P-чат
/help — список команд, Ctrl-D — выход
"""

# Русские синонимы команд. В подсказках их нет намеренно: список из двадцати
# строк читается хуже, чем из десяти, а тот, кто пишет «/кто», и так получает
# ответ.
ALIASES = {
    "помощь": "help",
    "справка": "help",
    "кто": "peers",
    "участники": "peers",
    "отпечаток": "fingerprint",
    "сверить": "verify",
    "забыть": "forget",
    "подключить": "connect",
    "подключиться": "connect",
    "файл": "send",
    "отправить": "send",
    "принять": "accept",
    "отклонить": "decline",
    "лично": "w",
    "шепнуть": "w",
    "выход": "quit",
    "выйти": "quit",
}

HELP = """Команды:
  /w <ник> <текст>     сказать лично (ночные ходы в играх — только так)
  /peers               кто на связи
  /fingerprint         мой отпечаток
  /verify <ник>        отметить, что SAS сверен голосом
  /forget <ник>        забыть ключ (если собеседник переустановил чат)
  /connect host:port   подключиться вручную
  /send <ник> <путь>   предложить файл
  /accept <id>         принять предложенный файл
  /decline <id>        отказаться
  /quit                выход
Всё, что не начинается со «/», уходит в чат.
Команды понимают и русские названия — список в README."""


class Console:
    def __init__(self, mesh: Mesh, trust: TrustStore, palette: Palette | None = None) -> None:
        self.mesh = mesh
        self.trust = trust
        self.palette = palette or build_palette()
        self._running = True

    async def run(self) -> None:
        print(BANNER)
        await self.mesh.start()
        pump = asyncio.create_task(self._pump_events())
        try:
            await self._input_loop()
        finally:
            self._running = False
            pump.cancel()
            await self.mesh.stop()

    # --- вывод ---------------------------------------------------------------

    async def _pump_events(self) -> None:
        while True:
            self._write(self._decorate(await self.mesh.events.get()))

    def _decorate(self, event: ev.Event) -> str:
        """Цвет добавляется здесь и только здесь — в сеть он не уходит."""
        colors = self.palette

        if isinstance(event, ev.TextMessage):
            text = sanitize(event.text)
            if event.is_bot:
                return "\n".join(colors.bot(f"┃ {line}") for line in text.split("\n"))
            mark = "" if self._is_verified(event.public) else colors.yellow("?")
            return f"{mark}{colors.nick(event.nick, event.public)}: {text}"

        if isinstance(event, ev.Alert):
            return colors.red(colors.bold(event.render()))
        if isinstance(event, ev.PeerConnected):
            return colors.green(event.render())
        if isinstance(event, ev.PeerDisconnected):
            return colors.grey(event.render())
        if isinstance(event, (ev.FileFinished, ev.FileSent)):
            return colors.green(event.render())
        if isinstance(event, ev.FileFailed):
            return colors.red(event.render())
        if isinstance(event, ev.FileOffered):
            return colors.blue(event.render())
        return colors.grey(event.render())

    def _write(self, text: str) -> None:
        print(text, flush=True)

    def _is_verified(self, public: bytes) -> bool:
        record = self.trust.by_key(public)
        return bool(record and record.verified)

    # --- ввод ----------------------------------------------------------------

    async def _input_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
            except (EOFError, KeyboardInterrupt):
                break
            if not line:  # Ctrl-D
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                if not await self._command(line):
                    break
            else:
                await self.mesh.broadcast(line)

    async def _command(self, line: str) -> bool:
        """Возвращает False, если пора выходить."""
        name, _, rest = line[1:].partition(" ")
        name = name.lower()
        name = ALIASES.get(name, name)
        rest = rest.strip()

        if name in ("quit", "exit"):
            return False

        if name == "help":
            self._write(HELP)
        elif name in ("w", "msg", "tell"):
            nick, _, body = rest.partition(" ")
            body = body.strip()
            if not nick or not body:
                self._write("* формат: /w <ник> <текст>")
            elif await self.mesh.send_text(nick, body):
                self._write(self.palette.dim(f"→ {nick}: {body}"))
            else:
                self._write(f"* {nick} не на связи")
        elif name == "peers":
            peers = self.mesh.peers
            self._write("На связи: " + (", ".join(peers) if peers else "никого"))
        elif name == "fingerprint":
            self._write(f"Мой отпечаток: {self.mesh.identity.fingerprint()}")
        elif name == "verify":
            if self.trust.mark_verified(rest):
                self._write(self.palette.green(f"✓ {rest} отмечен как сверенный"))
            else:
                self._write(self.palette.red(f"✗ {rest} не найден среди известных"))
        elif name == "forget":
            if self.trust.forget(rest):
                self._write(f"* ключ {rest} забыт; при следующем соединении запомню новый")
            else:
                self._write(f"* {rest} и так неизвестен")
        elif name == "connect":
            host, _, port = rest.rpartition(":")
            if not host or not port.isdigit():
                self._write("* формат: /connect host:port")
            else:
                await self.mesh.connect_to(host, int(port))
        elif name == "send":
            nick, _, path = rest.partition(" ")
            if not nick or not path:
                self._write("* формат: /send <ник> <путь к файлу>")
            else:
                await self.mesh.offer_file(nick, Path(path.strip()).expanduser())
        elif name == "accept":
            await self.mesh.respond_to_offer(rest, accept=True)
        elif name == "decline":
            await self.mesh.respond_to_offer(rest, accept=False)
        else:
            self._write(f"* неизвестная команда {name}; /help покажет список")
        return True


class PromptToolkitConsole(Console):
    """Вариант с раздельными областями ввода и вывода."""

    def __init__(self, mesh: Mesh, trust: TrustStore, palette: Palette | None = None) -> None:
        super().__init__(mesh, trust, palette)
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout

        self._session = PromptSession()
        self._patch = patch_stdout

    async def _input_loop(self) -> None:
        with self._patch():
            while self._running:
                try:
                    line = (await self._session.prompt_async("> ")).strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    continue
                if line.startswith("/"):
                    if not await self._command(line):
                        break
                else:
                    await self.mesh.broadcast(line)


def build_console(mesh: Mesh, trust: TrustStore, palette: Palette | None = None) -> Console:
    try:
        return PromptToolkitConsole(mesh, trust, palette)
    except ImportError:
        return Console(mesh, trust, palette)
