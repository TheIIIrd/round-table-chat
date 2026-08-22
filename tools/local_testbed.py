#!/usr/bin/env python3
"""Локальный стенд: несколько участников и бот на одной машине.

Каждому участнику нужен свой каталог с ключом и свой порт — программа ничего
не знает о том, что соседи запущены рядом, и работает через настоящие сокеты
на 127.0.0.1. Скрипт готовит каталоги, ключи и общий ростер, а затем печатает
команды запуска.

    python tools/local_testbed.py                 # alice, bob, carol, бот dice
    python tools/local_testbed.py --reset         # снести и собрать заново
    python tools/local_testbed.py --users петя,вася --no-bot
    python tools/local_testbed.py --tmux          # сразу поднять всё в tmux

Пассфраза у стенда одна и известная («testbed-passphrase»). Это допустимо для
песочницы на localhost и недопустимо ни для чего другого.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
from pathlib import Path

# Скрипт запускают из корня репозитория как `python tools/local_testbed.py`,
# поэтому пакет надо найти до импорта — отсюда порядок, непривычный линтеру.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pylint: disable=wrong-import-position
from p2pchat.crypto.identity import Identity  # noqa: E402
from p2pchat.proto.roster import Roster  # noqa: E402

# pylint: enable=wrong-import-position

PASSPHRASE = "testbed-passphrase"
DEFAULT_ROOT = Path("/tmp/p2pchat-testbed")
FIRST_PORT = 9401


def free_port(preferred: int) -> int:
    """Берём предложенный порт, если он свободен, иначе любой свободный."""
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def build(root: Path, users: list[str], bot: str | None) -> tuple[dict[str, int], Path]:
    names = users + ([bot] if bot else [])
    ports = {name: free_port(FIRST_PORT + index) for index, name in enumerate(names)}

    entries = []
    for name in names:
        home = root / name
        home.mkdir(parents=True, exist_ok=True)
        identity = Identity.generate(name)
        identity.save(home / "id.key", PASSPHRASE)
        (home / "nick").write_text(name, encoding="utf-8")
        entry = {
            "nick": name,
            "key": identity.public.hex(),
            "address": f"127.0.0.1:{ports[name]}",
        }
        if name == bot:
            entry["bot"] = True
        entries.append(entry)

    roster = Roster.from_json({"name": "testbed", "members": entries})
    for name in names:
        roster.save(root / name / "roster.json")
    return ports, root


def commands(root: Path, users: list[str], bot: str | None, ports: dict[str, int]) -> list[str]:
    prefix = f"P2PCHAT_PASSPHRASE={PASSPHRASE} python -m p2pchat --home {root}"
    lines = [
        f"{prefix}/{name} chat --key-from-env --nick {name} "
        f"--listen 127.0.0.1:{ports[name]}"
        for name in users
    ]
    if bot:
        lines.append(
            f"{prefix}/{bot} bot --key-from-env --nick {bot} --listen 127.0.0.1:{ports[bot]}"
        )
    return lines


def launch_tmux(session: str, lines: list[str]) -> int:
    if shutil.which("tmux") is None:
        print("tmux не найден — запустите команды вручную в разных терминалах.")
        return 1
    subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True, check=False)
    subprocess.run(["tmux", "new-session", "-d", "-s", session, lines[0]], check=True)
    for line in lines[1:]:
        subprocess.run(["tmux", "split-window", "-t", session, line], check=True)
    subprocess.run(["tmux", "select-layout", "-t", session, "tiled"], check=True)
    print(f"Сессия tmux «{session}» поднята. Подключиться: tmux attach -t {session}")
    print(f"Остановить: tmux kill-session -t {session}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Локальный стенд p2pchat")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--users", default="alice,bob,carol", help="ники через запятую")
    parser.add_argument("--bot", default="dice", help="ник бота")
    parser.add_argument("--no-bot", action="store_true", help="без бота")
    parser.add_argument("--reset", action="store_true", help="удалить каталог и создать заново")
    parser.add_argument("--tmux", action="store_true", help="сразу запустить всех в tmux")
    args = parser.parse_args()

    users = [name.strip() for name in args.users.split(",") if name.strip()]
    bot = None if args.no_bot else args.bot
    if bot in users:
        print("Ник бота совпадает с ником участника", file=sys.stderr)
        return 1

    if args.reset and args.root.exists():
        shutil.rmtree(args.root)
    if args.root.exists() and any(args.root.iterdir()):
        print(f"Каталог {args.root} не пуст. Используйте --reset, чтобы пересобрать.")
        return 1

    ports, root = build(args.root, users, bot)
    roster = Roster.load(root / users[0] / "roster.json")

    print(f"Стенд готов: {root}")
    print(f"Группа «{roster.name}», идентификатор {roster.group_id.hex()}")
    for member in roster.members:
        mark = " [бот]" if member.is_bot else ""
        print(f"  {member.nick}{mark}: 127.0.0.1:{member.port}")

    lines = commands(root, users, bot, ports)
    if args.tmux:
        return launch_tmux("p2pchat", lines)

    print("\nЗапустите каждую команду в своём терминале:\n")
    for line in lines:
        print(f"  {line}\n")
    print("Внутри чата: /peers, /verify <ник>, !roll d20 — если бот в группе.")
    print(
        "\nПервые секунд десять группа собирается: при старте каждый процесс\n"
        "выводит ключ из пассфразы через Argon2id (256 МиБ), а запущенные разом\n"
        "клиенты делят один процессор. Дождитесь, пока /peers покажет всех."
    )
    print(f"Убрать стенд: rm -rf {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
