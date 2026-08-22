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

from ..format import sanitize, strip_ansi
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
            return colors.alert(event.render())
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
        """Выполняет команду. Возвращает False, если пора выходить.

        Разбор устроен таблицей, а не лестницей из elif: добавить команду —
        значит дописать одну строку в COMMANDS, а не ветку в растущий метод.
        """
        name, _, rest = line[1:].partition(" ")
        name = name.lower()
        name = ALIASES.get(name, name)
        rest = rest.strip()

        if name in ("quit", "exit"):
            return False

        handler = self.COMMANDS.get(name)
        if handler is None:
            self._write(f"· неизвестная команда {name}; /help покажет список")
            return True

        await handler(self, rest)
        return True

    # --- отдельные команды ----------------------------------------------------

    async def _cmd_help(self, _rest: str) -> None:
        self._write(HELP)

    async def _cmd_peers(self, _rest: str) -> None:
        peers = self.mesh.peers
        self._write("На связи: " + (", ".join(peers) if peers else "никого"))

    async def _cmd_fingerprint(self, _rest: str) -> None:
        self._write(f"Мой отпечаток: {self.mesh.identity.fingerprint()}")

    async def _cmd_verify(self, rest: str) -> None:
        if self.trust.mark_verified(rest):
            self._write(self.palette.green(f"✓ {rest} отмечен как сверенный"))
        else:
            self._write(self.palette.red(f"✗ {rest} не найден среди известных"))

    async def _cmd_forget(self, rest: str) -> None:
        if self.trust.forget(rest):
            self._write(f"· ключ {rest} забыт; при следующем соединении запомню новый")
        else:
            self._write(f"· {rest} и так неизвестен")

    async def _cmd_connect(self, rest: str) -> None:
        host, _, port = rest.rpartition(":")
        if not host or not port.isdigit():
            self._write("· формат: /connect host:port")
            return
        await self.mesh.connect_to(host, int(port))

    async def _cmd_send(self, rest: str) -> None:
        nick, _, path = rest.partition(" ")
        if not nick or not path.strip():
            self._write("· формат: /send <ник> <путь к файлу>")
            return
        await self.mesh.offer_file(nick, Path(path.strip()).expanduser())

    async def _cmd_accept(self, rest: str) -> None:
        await self.mesh.respond_to_offer(rest, accept=True)

    async def _cmd_decline(self, rest: str) -> None:
        await self.mesh.respond_to_offer(rest, accept=False)

    async def _cmd_whisper(self, rest: str) -> None:
        nick, _, body = rest.partition(" ")
        body = body.strip()
        if not nick or not body:
            self._write("· формат: /w <ник> <текст>")
        elif await self.mesh.send_text(nick, body):
            self._write(self.palette.dim(f"→ {nick}: {body}"))
        else:
            self._write(f"· {nick} не на связи")

    COMMANDS = {
        "help": _cmd_help,
        "peers": _cmd_peers,
        "fingerprint": _cmd_fingerprint,
        "verify": _cmd_verify,
        "forget": _cmd_forget,
        "connect": _cmd_connect,
        "send": _cmd_send,
        "accept": _cmd_accept,
        "decline": _cmd_decline,
        "w": _cmd_whisper,
        "msg": _cmd_whisper,
        "tell": _cmd_whisper,
    }


class PromptToolkitConsole(Console):
    """Вариант с раздельными областями ввода и вывода.

    Важная особенность, из-за которой здесь переопределён ``_write``:
    ``patch_stdout()`` перехватывает обычный ``print`` и пропускает его через
    ``Vt100_Output.write()``, который заменяет ``\x1b`` на ``?`` — защита от
    того, чтобы печатаемый текст управлял терминалом. Наши ANSI-коды попадают
    под ту же замену, и вместо цвета на экране появляется ``?[38;5;114m``.

    Правильный путь — отдавать цвет через собственный API библиотеки:
    ``print_formatted_text(ANSI(...))`` разбирает последовательности сам и
    рисует их своими средствами.
    """

    def __init__(self, mesh: Mesh, trust: TrustStore, palette: Palette | None = None) -> None:
        super().__init__(mesh, trust, palette)
        from prompt_toolkit import PromptSession, print_formatted_text
        from prompt_toolkit.formatted_text import ANSI
        from prompt_toolkit.patch_stdout import patch_stdout

        self._session = PromptSession()
        self._patch = patch_stdout
        self._print = print_formatted_text
        self._ansi = ANSI

    def _write(self, text: str) -> None:
        if not self.palette.enabled:
            print(text, flush=True)
            return
        try:
            self._print(self._ansi(text))
        except Exception:  # pylint: disable=broad-exception-caught
            # Библиотека могла не справиться с последовательностью. Показать
            # текст без цвета лучше, чем не показать сообщение вовсе.
            print(strip_ansi(text), flush=True)

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


def build_console(
    mesh: Mesh,
    trust: TrustStore,
    palette: Palette | None = None,
    *,
    plain: bool = False,
) -> Console:
    """Выбирает интерфейс.

    ``plain`` заставляет взять простой вариант даже там, где prompt_toolkit
    установлен: если библиотека в конкретном терминале ведёт себя странно,
    у человека должен быть способ обойти её, не удаляя пакет.
    """
    if plain:
        return Console(mesh, trust, palette)
    try:
        return PromptToolkitConsole(mesh, trust, palette)
    except Exception:  # pylint: disable=broad-exception-caught
        # Библиотеки может не быть, а может быть — и падать на этом терминале.
        # Простой интерфейс работает всегда, поэтому откат молчаливый.
        return Console(mesh, trust, palette)
