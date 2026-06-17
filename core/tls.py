"""
TLS support for encrypted transport.
Самоподписанные сертификаты для сервера и клиентов.

Генерация:
- Серверный сертификат (server.crt / server.key)
- Клиентские сертификаты (опционально, для mutual TLS)
"""

import datetime
import os
import ssl
from pathlib import Path
from typing import Optional, Tuple


# Пути к сертификатам по умолчанию
DEFAULT_CERT_DIR = Path.home() / ".group-chat" / "certs"
SERVER_CERT_FILE = "server.crt"
SERVER_KEY_FILE = "server.key"
CA_CERT_FILE = "ca.crt"
CA_KEY_FILE = "ca.key"


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    common_name: str = "localhost",
    days_valid: int = 365
) -> None:
    """
    Генерирует самоподписанный сертификат.

    Использует cryptography (уже есть в зависимостях).
    Не требует openssl в системе.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert_path.parent.mkdir(parents=True, exist_ok=True)

    # Генерируем ключ
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Сохраняем ключ
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Создаём сертификат
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Group Chat"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Делаем ключ доступным только владельцу (Unix)
    if os.name != 'nt':
        os.chmod(key_path, 0o600)


def create_server_ssl_context(
    cert_dir: Optional[Path] = None,
    auto_generate: bool = True
) -> Tuple[ssl.SSLContext, Path, Path]:
    """
    Создаёт SSL-контекст для сервера.

    Если сертификатов нет и auto_generate=True — создаёт самоподписанные.

    Returns:
        (ssl_context, cert_path, key_path)
    """
    if cert_dir is None:
        cert_dir = DEFAULT_CERT_DIR

    cert_path = cert_dir / SERVER_CERT_FILE
    key_path = cert_dir / SERVER_KEY_FILE

    if not cert_path.exists() or not key_path.exists():
        if auto_generate:
            print(f"[TLS] Generating self-signed certificate in {cert_dir}...")
            generate_self_signed_cert(cert_path, key_path, "localhost")
            print(f"[TLS] Certificate generated: {cert_path}")
        else:
            raise FileNotFoundError(
                f"Certificate not found at {cert_path}. "
                f"Generate with: python -m core.tls --generate"
            )

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(str(cert_path), str(key_path))

    # Для продакшена: требовать сертификаты от клиентов
    # context.verify_mode = ssl.CERT_REQUIRED
    # context.load_verify_locations(cafile=str(cert_dir / CA_CERT_FILE))

    # Пока без client cert verification
    context.verify_mode = ssl.CERT_NONE

    return context, cert_path, key_path


def create_client_ssl_context(
    server_hostname: str = "localhost",
    check_hostname: bool = False
) -> ssl.SSLContext:
    """
    Создаёт SSL-контекст для клиента.

    Для самоподписанных сертификатов check_hostname должен быть False.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    if not check_hostname:
        # Для самоподписанных сертификатов
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


# Утилита командной строки для генерации сертификатов
if __name__ == "__main__":
    import argparse
    import ipaddress

    parser = argparse.ArgumentParser(description="TLS certificate generator")
    parser.add_argument("--generate", action="store_true", help="Generate certificates")
    parser.add_argument("--cert-dir", default=str(DEFAULT_CERT_DIR), help="Certificate directory")
    parser.add_argument("--host", default="localhost", help="Server hostname")
    args = parser.parse_args()

    if args.generate:
        cert_dir = Path(args.cert_dir)
        cert_path = cert_dir / SERVER_CERT_FILE
        key_path = cert_dir / SERVER_KEY_FILE

        generate_self_signed_cert(cert_path, key_path, args.host)
        print(f"Generated:")
        print(f"  Certificate: {cert_path}")
        print(f"  Private key: {key_path}")
        print(f"\nFor production, replace with real certificates from Let's Encrypt or internal CA.")
