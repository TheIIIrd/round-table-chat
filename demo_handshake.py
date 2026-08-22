#!/usr/bin/env python3
"""Наглядная демонстрация первого этапа: хендшейк, SAS, транспорт.

Сети здесь нет — сообщения передаются переменными. Это ровно то, что потом
поедет через ``Link`` на третьем этапе, без единого изменения в криптослое.

    python3 demo_handshake.py
"""

from __future__ import annotations

from p2pchat.crypto import primitives as p
from p2pchat.crypto.identity import Identity, fingerprint
from p2pchat.crypto.noise_xx import HandshakeState
from p2pchat.crypto.sas import sas_code

PROLOGUE = b"p2pchat/1 mode=direct"


def show_identities(alice: Identity, bob: Identity) -> None:
    print("Долговременные отпечатки (публикуются заранее):")
    print(f"  alice  {alice.fingerprint()}")
    print(f"  bob    {bob.fingerprint()}\n")


def exchange(hs_a: HandshakeState, hs_b: HandshakeState) -> None:
    """Три сообщения паттерна XX с пояснением, что видно в каждом."""
    first = hs_a.write_message()
    hs_b.read_message(first)
    print(f"-> e            {len(first):3d} байт   (статический ключ ещё не раскрыт)")

    second = hs_b.write_message()
    hs_a.read_message(second)
    print(f"<- e, ee, s, es {len(second):3d} байт   (ключ Боба уже под шифром)")

    third = hs_a.write_message(b"alice")
    nick = hs_b.read_message(third)
    print(f"-> s, se        {len(third):3d} байт   полезная нагрузка: {nick.decode()!r}\n")


def main() -> None:
    """Проводит хендшейк между двумя сторонами и печатает, что при этом видно."""
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    show_identities(alice, bob)

    hs_a = HandshakeState(initiator=True, static=alice.keypair, prologue=PROLOGUE)
    hs_b = HandshakeState(initiator=False, static=bob.keypair, prologue=PROLOGUE)
    exchange(hs_a, hs_b)

    print("Каждая сторона видит статический ключ собеседника:")
    print(f"  Алиса опознала: {fingerprint(hs_a.remote_static)}  == bob:   "
          f"{fingerprint(hs_a.remote_static) == bob.fingerprint()}")
    print(f"  Боб опознал:    {fingerprint(hs_b.remote_static)}  == alice: "
          f"{fingerprint(hs_b.remote_static) == alice.fingerprint()}\n")

    code = sas_code(hs_a.handshake_hash)
    print("SAS — прочитать вслух по независимому каналу и сверить:")
    print(f"  {code}")
    print(f"  совпадает у обеих сторон: {code == sas_code(hs_b.handshake_hash)}\n")

    a_send, a_recv = hs_a.split()
    b_send, b_recv = hs_b.split()

    for text in ("привет", "как транспорт?", "работает"):
        ct = a_send.encrypt_with_ad(b"", text.encode())
        print(f"  {len(ct):3d} байт шифротекста -> {b_recv.decrypt_with_ad(b'', ct).decode()}")

    reply = b_send.encrypt_with_ad(b"", "и обратно тоже".encode())
    print(f"  {len(reply):3d} байт шифротекста <- {a_recv.decrypt_with_ad(b'', reply).decode()}")

    try:
        b_recv.decrypt_with_ad(b"", ct)
    except p.InvalidTag:
        print("\nПовтор старого шифротекста отвергнут — счётчик nonce уже ушёл вперёд.")


if __name__ == "__main__":
    main()
