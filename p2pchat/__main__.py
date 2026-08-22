"""Командная строка p2pchat.

    p2pchat keygen                     создать долговременный ключ
    p2pchat whoami                     показать свой публичный ключ и отпечаток
    p2pchat roster new|add|show        собрать файл группы
    p2pchat chat                       групповой чат по ростеру
    p2pchat chat --direct host:port    разговор один на один
    p2pchat bot                        запустить бота
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from .bot.runner import Bot
from .crypto.identity import Identity, KeyFileError, fingerprint
from .proto import invite as invites
from .proto.invite import InviteError
from .proto.mesh import Mesh
from .proto.roster import Member, Roster, RosterError
from .proto.trust import TrustStore
from .ui.console import build_console
from .ui.style import build_palette

DEFAULT_HOME = Path(os.environ.get("P2PCHAT_HOME", Path.home() / ".p2pchat"))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    try:
        return args.handler(args)
    except (KeyFileError, RosterError, InviteError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="p2pchat", description="Безопасный консольный P2P-чат")
    parser.add_argument(
        "--home", type=Path, default=DEFAULT_HOME, help="каталог с ключом и данными"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="вывод без цвета (то же делает переменная NO_COLOR)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="создать долговременный ключ")
    keygen.add_argument("--nick", default=getpass.getuser(), help="ник по умолчанию")
    keygen.add_argument(
        "--key-from-env",
        action="store_true",
        help="взять пассфразу из P2PCHAT_PASSPHRASE (для скриптов и локальных стендов)",
    )
    keygen.set_defaults(handler=cmd_keygen)

    whoami = sub.add_parser("whoami", help="показать свой ключ и отпечаток")
    whoami.set_defaults(handler=cmd_whoami)

    roster = sub.add_parser("roster", help="работа с составом группы")
    roster_sub = roster.add_subparsers(dest="action", required=True)

    r_new = roster_sub.add_parser("new", help="создать пустой ростер")
    r_new.add_argument("name")
    r_new.set_defaults(handler=cmd_roster_new)

    r_add = roster_sub.add_parser("add", help="добавить участника")
    r_add.add_argument("nick")
    r_add.add_argument("key", help="публичный ключ в hex")
    r_add.add_argument("--address", help="host:port, если участник принимает соединения")
    r_add.add_argument("--bot", action="store_true", help="пометить как бота")
    r_add.set_defaults(handler=cmd_roster_add)

    r_invite = roster_sub.add_parser("add-invite", help="добавить участника из приглашения")
    r_invite.add_argument("invite", help="строка p2pchat:… или p2pchat-group:…")
    r_invite.set_defaults(handler=cmd_roster_add_invite)

    r_show = roster_sub.add_parser("show", help="показать состав и идентификатор группы")
    r_show.set_defaults(handler=cmd_roster_show)

    invite = sub.add_parser("invite", help="показать свою строку-приглашение")
    invite.add_argument("--address", help="host:port, под которым вас видно снаружи")
    invite.add_argument("--group", action="store_true", help="приглашение со всем ростером")
    invite.set_defaults(handler=cmd_invite)

    chat = sub.add_parser("chat", help="запустить чат")
    chat.add_argument("--nick", help="ник (по умолчанию из ключа)")
    chat.add_argument("--listen", default="0.0.0.0:9333", help="адрес для входящих, или none")
    chat.add_argument("--direct", help="host:port собеседника для режима один на один")
    chat.add_argument(
        "--discover",
        choices=["lan", "off"],
        default="off",
        help="lan — искать участников в локальной сети мультикастом",
    )
    chat.add_argument(
        "--key-from-env",
        action="store_true",
        help="взять пассфразу из P2PCHAT_PASSPHRASE (для скриптов; обычно не нужно)",
    )
    chat.set_defaults(handler=cmd_chat)

    bot = sub.add_parser("bot", help="запустить бота")
    bot.add_argument("--nick", default="dice", help="ник бота")
    bot.add_argument("--listen", default="0.0.0.0:9334")
    bot.add_argument("--discover", choices=["lan", "off"], default="off")
    bot.add_argument(
        "--key-from-env",
        action="store_true",
        help="взять пассфразу из P2PCHAT_PASSPHRASE (нужно для автоперезапуска)",
    )
    bot.set_defaults(handler=cmd_bot)

    return parser


# --- команды ----------------------------------------------------------------


def cmd_keygen(args) -> int:
    home: Path = args.home
    home.mkdir(parents=True, exist_ok=True)
    path = home / "id.key"
    if path.exists():
        print(f"Ключ уже существует: {path}", file=sys.stderr)
        return 1

    if args.key_from_env:
        passphrase = os.environ.get("P2PCHAT_PASSPHRASE", "")
        if len(passphrase) < 8:
            raise ValueError("P2PCHAT_PASSPHRASE пуста или короче восьми символов")
    else:
        passphrase = _ask_new_passphrase()
    identity = Identity.generate(args.nick)
    identity.save(path, passphrase)
    (home / "nick").write_text(args.nick, encoding="utf-8")

    print(f"Ключ создан: {path}")
    print(f"Ник:         {args.nick}")
    print(f"Отпечаток:   {identity.fingerprint()}")
    print(f"Публичный:   {identity.public.hex()}")
    print("\nПередайте публичный ключ остальным участникам — он идёт в ростер.")
    return 0


def cmd_whoami(args) -> int:
    identity = _load_identity(args)
    print(f"Ник:       {_default_nick(args)}")
    print(f"Отпечаток: {identity.fingerprint()}")
    print(f"Публичный: {identity.public.hex()}")
    return 0


def cmd_roster_new(args) -> int:
    path = _roster_path(args)
    if path.exists():
        print(f"Ростер уже существует: {path}", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"name": args.name, "members": []}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Создан пустой ростер: {path}")
    print("Добавьте участников: p2pchat roster add <ник> <публичный ключ> --address host:port")
    return 0


def cmd_roster_add(args) -> int:
    path = _roster_path(args)
    raw = json.loads(path.read_text())
    raw.setdefault("members", [])

    entry: dict = {"nick": args.nick, "key": args.key}
    if args.address:
        entry["address"] = args.address
    if args.bot:
        entry["bot"] = True
    raw["members"].append(entry)

    roster = Roster.from_json(raw)  # проверка до записи
    roster.save(path)
    print(f"Добавлен {args.nick}. Участников: {len(roster.members)}")
    print(f"Новый идентификатор группы: {roster.group_id.hex()}")
    print("Раздайте обновлённый файл всем — со старым составом соединения не будет.")
    return 0


def cmd_roster_show(args) -> int:
    roster = Roster.load(_roster_path(args))
    print(f"Группа «{roster.name}», идентификатор {roster.group_id.hex()}")
    for member in roster.members:
        address = f"{member.host}:{member.port}" if member.address else "без адреса"
        mark = " [бот]" if member.is_bot else ""
        print(f"  {member.nick}{mark}: {member.public.hex()[:16]}… {address}")
    return 0


def cmd_invite(args) -> int:
    identity = _load_identity(args)
    nick = _default_nick(args)

    if args.group:
        roster = Roster.load(_roster_path(args))
        print(invites.encode_group(roster))
        print(f"\nГруппа «{roster.name}», участников: {len(roster.members)}")
        print("Принять: p2pchat roster add-invite <строка>")
        return 0

    host, port = (_split_address(args.address) if args.address else (None, None))
    if host is None:
        roster_file = _roster_path(args)
        if roster_file.exists():
            member = Roster.load(roster_file).by_key(identity.public)
            if member and member.address:
                host, port = member.address
    member = Member(nick=nick, public=identity.public, host=host, port=port)

    print(invites.encode_peer(member))
    print(f"\nОтпечаток: {identity.fingerprint()}")
    if host is None:
        print("Адрес не указан — добавьте --address host:port, иначе к вам не дозвонятся.")
    print("Продиктуйте отпечаток голосом: строку могли подменить по дороге.")
    return 0


def cmd_roster_add_invite(args) -> int:
    path = _roster_path(args)
    text = args.invite.strip()

    if invites.looks_like_group(text):
        roster = invites.decode_group(text)
        roster.save(path)
        print(f"Ростер принят: группа «{roster.name}», участников {len(roster.members)}")
        print(f"Идентификатор группы: {roster.group_id.hex()}")
        for member in roster.members:
            print(f"  {member.nick}: {fingerprint(member.public)}")
        print("\nСверьте отпечатки с людьми напрямую — приглашение могли подменить.")
        return 0

    parsed = invites.decode_peer(text)
    raw = json.loads(path.read_text()) if path.exists() else {"name": "group", "members": []}
    raw.setdefault("members", [])
    raw["members"].append(parsed.member.to_json())

    roster = Roster.from_json(raw)  # проверка до записи
    roster.save(path)
    print(f"Добавлен {parsed.member.nick}")
    print(f"Отпечаток: {parsed.fingerprint}")
    print(f"Новый идентификатор группы: {roster.group_id.hex()}")
    print("Раздайте обновлённый ростер всем: p2pchat invite --group")
    return 0


def cmd_chat(args) -> int:
    identity = _load_identity(args, from_env=args.key_from_env)
    nick = args.nick or _default_nick(args)
    trust = TrustStore.load(args.home / "known_peers.json")
    listen = _parse_listen(args.listen)

    roster = None
    if not args.direct:
        roster = Roster.load(_roster_path(args))
        if roster.by_key(identity.public) is None:
            print("Вашего ключа нет в ростере — остальные вас не пустят.", file=sys.stderr)
            return 1

    mesh = Mesh(
        identity,
        nickname=nick,
        roster=roster,
        trust=trust,
        download_dir=args.home / "downloads",
        listen=listen,
        discover_lan=args.discover == "lan",
    )
    console = build_console(mesh, trust, build_palette(False if args.no_color else None))

    async def run() -> None:
        if args.direct:
            host, port = _split_address(args.direct)
            asyncio.get_running_loop().call_later(
                0.1, lambda: asyncio.ensure_future(mesh.connect_to(host, port))
            )
        await console.run()

    asyncio.run(run())
    return 0


def cmd_bot(args) -> int:
    identity = _load_identity(args, from_env=args.key_from_env)
    roster = Roster.load(_roster_path(args))
    member = roster.by_key(identity.public)
    if member is None:
        print("Ключа бота нет в ростере.", file=sys.stderr)
        return 1
    if not member.is_bot:
        print("Предупреждение: в ростере участник не помечен как бот.", file=sys.stderr)

    bot = Bot(
        identity,
        nickname=args.nick,
        roster=roster,
        trust_path=args.home / "bot_known_peers.json",
        listen=_parse_listen(args.listen),
        discover_lan=args.discover == "lan",
    )
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        pass
    return 0


# --- вспомогательное ---------------------------------------------------------


def _roster_path(args) -> Path:
    return args.home / "roster.json"


def _default_nick(args) -> str:
    nick_file = args.home / "nick"
    return nick_file.read_text().strip() if nick_file.exists() else getpass.getuser()


def _load_identity(args, *, from_env: bool = False) -> Identity:
    path = args.home / "id.key"
    if not path.exists():
        raise ValueError(f"нет ключа {path} — сначала выполните: p2pchat keygen")
    if from_env:
        passphrase = os.environ.get("P2PCHAT_PASSPHRASE")
        if not passphrase:
            raise ValueError("переменная P2PCHAT_PASSPHRASE пуста")
    else:
        passphrase = getpass.getpass("Пассфраза ключа: ")
    return Identity.load(path, passphrase, nickname=_default_nick(args))


def _ask_new_passphrase() -> str:
    first = getpass.getpass("Пассфраза для нового ключа: ")
    if len(first) < 8:
        raise ValueError("пассфраза короче восьми символов")
    if first != getpass.getpass("Повторите: "):
        raise ValueError("пассфразы не совпали")
    return first


def _parse_listen(value: str) -> tuple[str, int] | None:
    if value.lower() in ("none", "off", ""):
        return None
    return _split_address(value)


def _split_address(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"адрес должен быть в виде host:port, получено {value!r}")
    return host, int(port)


if __name__ == "__main__":
    raise SystemExit(main())
