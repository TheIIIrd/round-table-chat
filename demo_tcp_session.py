#!/usr/bin/env python3
"""Два пира в одном процессе разговаривают через реальный сокет.

Показывает то, что даёт третий этап: кадрирование, хендшейк поверх канала,
совпадение SAS у сторон и смену ключей прямо посреди разговора.

    python3 demo_tcp_session.py
"""

from __future__ import annotations

import asyncio

from p2pchat.crypto.identity import Identity, fingerprint
from p2pchat.net.link import LinkClosed
from p2pchat.net.tcp import TcpLink, serve
from p2pchat.proto.session import Session, build_prologue

PROLOGUE = build_prologue(mode="direct")


async def responder_side(link) -> None:
    """Отвечающая сторона: принимает соединение и повторяет присланное."""
    identity = Identity.generate("bob")
    session = await Session.accept(link, identity, prologue=PROLOGUE, payload=b"bob")
    print(f"[bob]   пир представился ключом {fingerprint(session.remote_static)}")
    print(f"[bob]   SAS: {session.sas}")
    try:
        async for message in session:
            text = message.decode()
            print(f"[bob]   получено: {text}")
            await session.send(f"принял «{text}»".encode())
    finally:
        await session.close()


async def main() -> None:
    """Поднимает сервер и клиента в одном процессе и гоняет между ними трафик."""
    identity = Identity.generate("alice")
    server = await serve("127.0.0.1", 0, responder_side)
    port = server.sockets[0].getsockname()[1]
    print(f"Слушаю 127.0.0.1:{port}\n")

    link = await TcpLink.connect("127.0.0.1", port)
    session = await Session.initiate(link, identity, prologue=PROLOGUE, payload=b"alice")

    print(f"[alice] пир представился ключом {fingerprint(session.remote_static)}")
    print(f"[alice] SAS: {session.sas}")
    print("[alice] коды должны совпасть — их и сверяют голосом\n")

    for text in ("привет", "как слышно?"):
        await session.send(text.encode())
        print(f"[alice] ответ: {(await session.receive()).decode()}")

    print("\n--- ротация ключей свежим DH ---")
    before = session.rekey_count
    await session.rekey()
    print(f"[alice] ротаций ключа: было {before}, стало {session.rekey_count}")
    print("[alice] старые ключи больше не расшифруют новый трафик\n")

    await session.send("сообщение в новой эпохе".encode())
    print(f"[alice] ответ: {(await session.receive()).decode()}")

    await session.close()
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except LinkClosed as exc:
        print(f"соединение потеряно: {exc}")
