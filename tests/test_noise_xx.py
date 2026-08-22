"""Тесты криптоядра: хендшейк, транспорт, устойчивость к подделке."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

import pytest

from p2pchat.crypto import primitives as p
from p2pchat.crypto.noise import CipherState, NoiseError
from p2pchat.crypto.noise_xx import HandshakeState
from p2pchat.crypto.sas import sas_code, sas_matches


def run_handshake(prologue: bytes = b"", payloads: tuple[bytes, ...] = (b"", b"", b"")):
    alice_s = p.KeyPair.generate()
    bob_s = p.KeyPair.generate()
    alice = HandshakeState(initiator=True, static=alice_s, prologue=prologue)
    bob = HandshakeState(initiator=False, static=bob_s, prologue=prologue)

    received = []
    received.append(bob.read_message(alice.write_message(payloads[0])))
    received.append(alice.read_message(bob.write_message(payloads[1])))
    received.append(bob.read_message(alice.write_message(payloads[2])))
    return alice, bob, received


def test_handshake_completes_and_agrees():
    alice, bob, payloads = run_handshake(prologue=b"p2pchat/1 group=abc")

    assert alice.is_complete and bob.is_complete
    assert payloads == [b"", b"", b""]
    # Обе стороны получили статический ключ друг друга...
    assert alice.remote_static == bob.s.public
    assert bob.remote_static == alice.s.public
    # ...и сошлись на одной стенограмме.
    assert alice.handshake_hash == bob.handshake_hash


def test_handshake_carries_payloads():
    _, _, payloads = run_handshake(payloads=(b"", b"hello from bob", b"and from alice"))
    assert payloads == [b"", b"hello from bob", b"and from alice"]


def test_first_message_does_not_leak_static_key():
    """В XX статический ключ инициатора уходит только в третьем сообщении."""
    alice_s = p.KeyPair.generate()
    alice = HandshakeState(initiator=True, static=alice_s)
    first = alice.write_message()
    assert alice_s.public not in first
    assert len(first) == p.DHLEN  # только эфемерный ключ, полезной нагрузки нет


def test_prologue_mismatch_breaks_handshake():
    """Разный prologue = разный контекст: третье сообщение не пройдёт проверку."""
    alice = HandshakeState(initiator=True, static=p.KeyPair.generate(), prologue=b"group=A")
    bob = HandshakeState(initiator=False, static=p.KeyPair.generate(), prologue=b"group=B")

    bob.read_message(alice.write_message())
    with pytest.raises(p.InvalidTag):
        alice.read_message(bob.write_message())


def test_transport_roundtrip_both_directions():
    alice, bob, _ = run_handshake()
    a_send, a_recv = alice.split()
    b_send, b_recv = bob.split()

    for i in range(64):
        msg = f"сообщение {i}".encode()
        assert b_recv.decrypt_with_ad(b"", a_send.encrypt_with_ad(b"", msg)) == msg
        reply = f"ответ {i}".encode()
        assert a_recv.decrypt_with_ad(b"", b_send.encrypt_with_ad(b"", reply)) == reply


def test_tampered_ciphertext_is_rejected():
    alice, bob, _ = run_handshake()
    a_send, _ = alice.split()
    _, b_recv = bob.split()

    ct = bytearray(a_send.encrypt_with_ad(b"", "перевод 10 рублей".encode()))
    ct[5] ^= 0x01
    with pytest.raises(p.InvalidTag):
        b_recv.decrypt_with_ad(b"", bytes(ct))


def test_failed_decryption_does_not_advance_nonce():
    """Подделанное сообщение не должно рассинхронизировать счётчики сторон."""
    alice, bob, _ = run_handshake()
    a_send, _ = alice.split()
    _, b_recv = bob.split()

    good = a_send.encrypt_with_ad(b"", b"ok")
    with pytest.raises(p.InvalidTag):
        b_recv.decrypt_with_ad(b"", bytes(len(good)))
    assert b_recv.n == 0
    assert b_recv.decrypt_with_ad(b"", good) == b"ok"


def test_replay_is_rejected():
    alice, bob, _ = run_handshake()
    a_send, _ = alice.split()
    _, b_recv = bob.split()

    ct = a_send.encrypt_with_ad(b"", b"once")
    assert b_recv.decrypt_with_ad(b"", ct) == b"once"
    with pytest.raises(p.InvalidTag):
        b_recv.decrypt_with_ad(b"", ct)  # тот же шифротекст на следующем nonce


def test_associated_data_is_bound():
    alice, bob, _ = run_handshake()
    a_send, _ = alice.split()
    _, b_recv = bob.split()

    ct = a_send.encrypt_with_ad(b"seq=1", b"payload")
    with pytest.raises(p.InvalidTag):
        b_recv.decrypt_with_ad(b"seq=2", ct)


def test_rekey_must_stay_in_sync():
    alice, bob, _ = run_handshake()
    a_send, _ = alice.split()
    _, b_recv = bob.split()

    a_send.rekey()
    ct = a_send.encrypt_with_ad(b"", "после ротации".encode())
    with pytest.raises(p.InvalidTag):
        b_recv.decrypt_with_ad(b"", ct)  # получатель ещё не прокрутил ключ

    b_recv.rekey()
    b_recv.set_nonce(a_send.n - 1)
    assert b_recv.decrypt_with_ad(b"", ct) == "после ротации".encode()


def test_turn_order_is_enforced():
    alice = HandshakeState(initiator=True, static=p.KeyPair.generate())
    bob = HandshakeState(initiator=False, static=p.KeyPair.generate())
    with pytest.raises(NoiseError):
        bob.write_message()  # отвечающий не может писать первым
    alice.write_message()
    with pytest.raises(NoiseError):
        alice.write_message()  # два раза подряд тоже нельзя


def test_truncated_message_is_rejected():
    alice = HandshakeState(initiator=True, static=p.KeyPair.generate())
    bob = HandshakeState(initiator=False, static=p.KeyPair.generate())
    with pytest.raises(NoiseError):
        bob.read_message(alice.write_message()[:10])


def test_degenerate_public_key_is_rejected():
    """Ключ малого порядка даёт нулевой общий секрет — такой пир отвергается."""
    kp = p.KeyPair.generate()
    with pytest.raises(p.BadKeyExchange):
        p.dh(kp, bytes(32))


def test_split_directions_do_not_cross():
    alice, bob, _ = run_handshake()
    a_send, a_recv = alice.split()
    b_send, b_recv = bob.split()
    assert a_send.k == b_recv.k
    assert a_recv.k == b_send.k
    assert a_send.k != a_recv.k


def test_sas_agrees_and_differs_per_session():
    alice, bob, _ = run_handshake()
    code = sas_code(alice.handshake_hash)
    assert code == sas_code(bob.handshake_hash)
    assert sas_matches(code, code.replace(" ", "-"))

    other_alice, _, _ = run_handshake()
    assert code != sas_code(other_alice.handshake_hash)


def test_sas_detects_man_in_the_middle():
    """Мэллори проводит два честных хендшейка — и получает два разных SAS."""
    alice_s, bob_s, mallory_s = (p.KeyPair.generate() for _ in range(3))

    alice = HandshakeState(initiator=True, static=alice_s)
    m_resp = HandshakeState(initiator=False, static=mallory_s)
    m_init = HandshakeState(initiator=True, static=mallory_s)
    bob = HandshakeState(initiator=False, static=bob_s)

    m_resp.read_message(alice.write_message())
    alice.read_message(m_resp.write_message())
    m_resp.read_message(alice.write_message())

    bob.read_message(m_init.write_message())
    m_init.read_message(bob.write_message())
    bob.read_message(m_init.write_message())

    # У каждого плеча свой хендшейк — и Алиса с Бобом называют разные коды.
    assert sas_code(alice.handshake_hash) != sas_code(bob.handshake_hash)


def test_cipherstate_without_key_passes_through():
    cs = CipherState()
    assert cs.encrypt_with_ad(b"ad", b"plain") == b"plain"
