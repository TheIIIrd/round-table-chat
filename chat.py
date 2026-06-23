#!/usr/bin/env python3
"""
Group Encrypted Chat with TUI (star topology, server relays)

Features:
- ECDH (secp384r1) + HKDF + Fernet
- TLS (опционально, самоподписанные сертификаты)
- Challenge-response auth (опционально, --password)
- E2E encryption (опционально, --e2e)
- Replay protection (nonce)
- Rate limiting

Usage:
  Server:  python chat.py --host 0.0.0.0 --port 8888 --nick Alice [--tls] [--password pwd] [--e2e]
  Client:  python chat.py --host 0.0.0.0 --port 8889 --peer HOST:PORT --nick Bob [--tls] [--password pwd] [--e2e]
"""

import argparse
import asyncio
import curses
import os
import sys
from pathlib import Path

from core.protocol import PROTOCOL_MAX_MESSAGE_SIZE
from core.tls import DEFAULT_CERT_DIR
from ui.chat_ui import ChatUI
from client.client import ChatClient
from utils.validators import validate_nickname
from utils.logging_config import setup_logging, get_logger

logger = get_logger(__name__)


def parse_args():
    """Парсит аргументы."""
    parser = argparse.ArgumentParser(
        description="Group Encrypted Chat with TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Простой сервер
  python chat.py --host 0.0.0.0 --port 8888 --nick Alice

  # Сервер с TLS, паролем и E2E
  python chat.py --host 0.0.0.0 --port 8888 --nick Alice --tls --password secret --e2e

  # Клиент к E2E-серверу
  python chat.py --host 0.0.0.0 --port 8889 --peer HOST:8888 --nick Bob --tls --password secret --e2e
        """
    )

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peer", default=None, help="Server address host:port")
    parser.add_argument("--nick", default="Anonymous")
    parser.add_argument("--password", default=None, help="Chat password")
    parser.add_argument("--tls", action="store_true", help="Enable TLS")
    parser.add_argument("--e2e", action="store_true", help="Enable E2E encryption")
    parser.add_argument("--cert-dir", default=str(DEFAULT_CERT_DIR))
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--version", action="version", version="Group Encrypted Chat v1.3.0")

    return parser.parse_args()


def validate_args(parsed_args) -> bool:
    """Валидация аргументов."""
    is_valid, error = validate_nickname(parsed_args.nick)
    if not is_valid:
        print(f"Invalid nickname: {error}", file=sys.stderr)
        return False

    if parsed_args.port < 1 or parsed_args.port > 65535:
        print(f"Invalid port: {parsed_args.port}", file=sys.stderr)
        return False

    if parsed_args.peer:
        from utils.validators import parse_peer_address
        _, _, error = parse_peer_address(parsed_args.peer)
        if error:
            print(f"Invalid peer address: {error}", file=sys.stderr)
            return False

    if parsed_args.password is not None and len(parsed_args.password) < 4:
        print("Password must be at least 4 characters", file=sys.stderr)
        return False

    if parsed_args.tls:
        cert_dir = Path(parsed_args.cert_dir)
        if not parsed_args.peer:
            server_cert = cert_dir / "server.crt"
            server_key = cert_dir / "server.key"
            if not server_cert.exists() or not server_key.exists():
                print(f"TLS enabled but no certificates in {cert_dir}", file=sys.stderr)
                print(f"Generate: python -m core.tls --generate", file=sys.stderr)
                return False

    if parsed_args.e2e and not parsed_args.peer:
        # Сервер с E2E — OK, клиент внутри тоже будет с E2E
        pass

    if os.name == 'nt':
        try:
            import curses
        except ImportError:
            print("On Windows: pip install windows-curses", file=sys.stderr)
            return False

    return True


async def input_loop(ui: ChatUI, client: ChatClient) -> None:
    """Главный цикл ввода."""
    while ui.running:
        try:
            key = ui.get_input_char()
            if key == curses.KEY_RESIZE:
                ui.resize()
                continue
            msg = ui.handle_input(key)
            if msg:
                await client.send_text(msg)
            await asyncio.sleep(0.01)
        except KeyboardInterrupt:
            ui.running = False
            break
        except Exception as e:
            logger.error("Error in input loop: %s", e)


def main(stdscr, parsed_args):
    """Точка входа curses."""
    ui = ChatUI(stdscr, parsed_args.nick)
    client = ChatClient(
        ui, parsed_args.host, parsed_args.port, parsed_args.peer,
        password=parsed_args.password,
        use_tls=parsed_args.tls,
        enable_e2e=parsed_args.e2e
    )

    async def run():
        try:
            await client.start()
            await input_loop(ui, client)
        except Exception as e:
            logger.exception("Fatal error: %s", e)
        finally:
            await client.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    args = parse_args()

    if not validate_args(args):
        sys.exit(1)

    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(
        level=getattr(__import__('logging'), log_level),
        log_file=args.log_file,
        module_levels={'core.crypto': 'WARNING'} if not args.debug else None
    )

    features = []
    if args.tls: features.append("TLS")
    if args.password: features.append("Auth")
    if args.e2e: features.append("E2E")
    features.extend(["Rate Limit", "Replay Protect"])

    # Показываем баннер
    print(f"""
            ########################################
            #     Group Encrypted Chat v1.2.0      #
            #     Star topology, ECDH + Fernet     #
            ########################################

            Features: {', '.join(features):<24}

            Nickname: {args.nick}
            Mode: {'SERVER + CLIENT' if not args.peer else 'CLIENT'}
            {'Peer: ' + args.peer if args.peer else 'Listening on ' + args.host + ':' + str(args.port)}
            Transport: {'TLS' if args.tls else 'TCP'}
            E2E: {'enabled' if args.e2e else 'disabled'}

            Connecting... (switch to TUI)

            """)

    try:
        curses.wrapper(main, args)
    except Exception as e:
        logger.exception("Curses wrapper failed: %s", e)
        sys.exit(1)
