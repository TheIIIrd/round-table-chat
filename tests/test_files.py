"""Тесты конечных автоматов передачи файлов."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

import pytest

from p2pchat.proto.files import (
    IncomingTransfer,
    OutgoingTransfer,
    TransferError,
    TransferState,
    encode_chunk,
    encode_offer,
    sanitize_name,
)


def test_sanitize_blocks_path_traversal():
    """Требование не «конкретная строка», а «результат безопасен как имя файла»."""
    dangerous = [
        "../../.ssh/authorized_keys",
        "/etc/passwd",
        "..\\..\\windows\\system32",
        "..",
        ".",
        "",
        "плохой\x00файл",
        "перенос\nстроки",
        "a" * 500,
    ]
    for raw in dangerous:
        name = sanitize_name(raw)
        assert name, f"{raw!r} дал пустое имя"
        assert "/" not in name and "\\" not in name
        assert not name.startswith(".")
        assert name not in {".", ".."}
        assert len(name) <= 120
        assert not any(ch < " " for ch in name)

    assert sanitize_name("отчёт.pdf") == "отчёт.pdf"  # нормальное имя не портим


def test_roundtrip_through_state_machines(tmp_path):
    payload = bytes(range(256)) * 400  # ~100 КиБ
    source = tmp_path / "отчёт.bin"
    source.write_bytes(payload)
    outbox = tmp_path / "downloads"

    sender = OutgoingTransfer(path=source)
    receiver = IncomingTransfer.from_offer(sender.offer_body(), outbox)
    assert receiver.name == "отчёт.bin" and receiver.size == len(payload)

    receiver.accept()
    for chunk in sender.chunks():
        receiver.add_chunk(chunk)
    result = receiver.finish()

    assert result.read_bytes() == payload
    assert receiver.state is TransferState.DONE
    assert not list(outbox.glob(".*.part"))


def test_corrupted_chunk_fails_hash_check(tmp_path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"A" * 5000)
    sender = OutgoingTransfer(path=source)
    receiver = IncomingTransfer.from_offer(sender.offer_body(), tmp_path / "out")
    receiver.accept()

    for index, chunk in enumerate(sender.chunks()):
        if index == 0:
            body = bytearray(chunk)
            body[-1] ^= 0xFF
            chunk = bytes(body)
        receiver.add_chunk(chunk)

    with pytest.raises(TransferError):
        receiver.finish()
    assert receiver.state is TransferState.FAILED
    assert not list((tmp_path / "out").iterdir())  # недоделанный файл не остаётся


def test_out_of_order_chunk_rejected(tmp_path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"B" * 100_000)
    sender = OutgoingTransfer(path=source)
    receiver = IncomingTransfer.from_offer(sender.offer_body(), tmp_path / "out")
    receiver.accept()

    chunks = list(sender.chunks())
    receiver.add_chunk(chunks[0])
    with pytest.raises(TransferError):
        receiver.add_chunk(chunks[2])


def test_oversized_offer_rejected(tmp_path):
    body = encode_offer(b"\x01" * 16, 10**12, b"\x02" * 32, "huge.bin")
    with pytest.raises(TransferError):
        IncomingTransfer.from_offer(body, tmp_path)


def test_sender_refuses_missing_and_empty(tmp_path):
    with pytest.raises(TransferError):
        OutgoingTransfer(path=tmp_path / "нет-такого")
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(TransferError):
        OutgoingTransfer(path=empty)


def test_more_data_than_declared_rejected(tmp_path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"C" * 100)
    sender = OutgoingTransfer(path=source)
    receiver = IncomingTransfer.from_offer(sender.offer_body(), tmp_path / "out")
    receiver.accept()
    with pytest.raises(TransferError):
        receiver.add_chunk(encode_chunk(sender.transfer_id, 0, b"D" * 200))


def test_declined_transfer_leaves_nothing(tmp_path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"E" * 1000)
    sender = OutgoingTransfer(path=source)
    outbox = tmp_path / "out"
    receiver = IncomingTransfer.from_offer(sender.offer_body(), outbox)
    receiver.accept()
    receiver.add_chunk(next(iter(sender.chunks())))
    receiver.decline()
    assert receiver.state is TransferState.DECLINED
    assert not outbox.exists() or not list(outbox.iterdir())


def test_existing_name_does_not_overwrite(tmp_path):
    outbox = tmp_path / "out"
    outbox.mkdir()
    (outbox / "data.bin").write_bytes("старое содержимое".encode())

    source = tmp_path / "data.bin"
    source.write_bytes("новое содержимое".encode())
    sender = OutgoingTransfer(path=source)
    receiver = IncomingTransfer.from_offer(sender.offer_body(), outbox)
    receiver.accept()
    for chunk in sender.chunks():
        receiver.add_chunk(chunk)
    result = receiver.finish()

    assert result.name == "data (1).bin"
    assert (outbox / "data.bin").read_bytes() == "старое содержимое".encode()


def test_chunk_fits_the_wire_with_room_to_spare():
    """Куски файла обязаны помещаться в кадр — и это не должно держаться на удаче.

    Величины живут в четырёх разных модулях: размер кадра, потолок полезной
    нагрузки сессии, заголовок конверта и размер куска. Правка любой из них без
    оглядки на остальные даёт «сообщение длиннее допустимого» уже во время
    передачи, а не при запуске.
    """
    from p2pchat.proto.envelope import HEADER_LEN
    from p2pchat.proto.files import CHUNK_SIZE, HASH_LEN, TRANSFER_ID_LEN
    from p2pchat.proto.session import MAX_PLAINTEXT

    chunk_message = HEADER_LEN + TRANSFER_ID_LEN + 4 + CHUNK_SIZE
    assert chunk_message <= MAX_PLAINTEXT

    # Предложение файла тоже едет одним сообщением: заголовок плюс длинное имя.
    offer_message = HEADER_LEN + TRANSFER_ID_LEN + 8 + HASH_LEN + 120 * 4
    assert offer_message <= MAX_PLAINTEXT
