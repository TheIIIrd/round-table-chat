"""Прогон официальных тест-векторов Noise.

Самопроверка (две наши реализации договорились друг с другом) ничего не
доказывает о совместимости: одинаковая ошибка с обеих сторон незаметна.
Реальную гарантию даёт совпадение с векторами, посчитанными чужой
реализацией — cacophony (Haskell) или snow (Rust).

Вектора прогонялись и совпали, но в репозиторий они не входят (чужой файл,
несколько мегабайт). На свежей копии тест пропускается, пока их не скачать::

    mkdir -p tests/vectors
    curl -L -o tests/vectors/cacophony.json \\
        https://raw.githubusercontent.com/mcginty/snow/master/tests/vectors/cacophony.txt

Тест сам найдёт наборы для Noise_XX_25519_ChaChaPoly_BLAKE2s и прогонит
хендшейк с зафиксированными эфемерными ключами, сверяя каждое сообщение
побайтово. Пока файла нет, тест помечается как пропущенный, а не как
пройденный — «зелёный» прогон без векторов ничего не значил бы.
"""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

import json
from pathlib import Path

import pytest

from p2pchat.crypto import primitives as p
from p2pchat.crypto.noise import PROTOCOL_NAME
from p2pchat.crypto.noise_xx import HandshakeState

VECTORS_DIR = Path(__file__).parent / "vectors"
PROTOCOL = PROTOCOL_NAME.decode()


def _load_vectors() -> list[dict]:
    if not VECTORS_DIR.is_dir():
        return []
    found = []
    for path in sorted(VECTORS_DIR.glob("*.json")) + sorted(VECTORS_DIR.glob("*.txt")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        entries = data.get("vectors", data if isinstance(data, list) else [])
        found += [v for v in entries if v.get("protocol_name") == PROTOCOL]
    return found


def _fixed_ephemerals(*raw_keys: str):
    """Отдаёт заранее заданные эфемерные ключи — иначе KAT невозможен."""
    keys = [p.KeyPair.from_private_bytes(bytes.fromhex(k)) for k in raw_keys]
    it = iter(keys)
    return lambda: next(it)


VECTORS = _load_vectors()


@pytest.mark.skipif(
    not VECTORS,
    reason=(
        "нет тест-векторов для " + PROTOCOL + "; см. docstring этого файла — "
        "положи cacophony.json в tests/vectors/"
    ),
)
def test_known_answer_vectors():
    for vector in VECTORS:
        init = HandshakeState(
            initiator=True,
            static=p.KeyPair.from_private_bytes(bytes.fromhex(vector["init_static"])),
            prologue=bytes.fromhex(vector.get("init_prologue", "")),
            ephemeral_factory=_fixed_ephemerals(vector["init_ephemeral"]),
        )
        resp = HandshakeState(
            initiator=False,
            static=p.KeyPair.from_private_bytes(bytes.fromhex(vector["resp_static"])),
            prologue=bytes.fromhex(vector.get("resp_prologue", "")),
            ephemeral_factory=_fixed_ephemerals(vector["resp_ephemeral"]),
        )

        writer, reader = init, resp
        for i, message in enumerate(vector["messages"]):
            payload = bytes.fromhex(message["payload"])
            expected = bytes.fromhex(message["ciphertext"])
            if writer.is_complete:
                break
            produced = writer.write_message(payload)
            assert produced == expected, f"{vector['protocol_name']}: сообщение {i}"
            assert reader.read_message(produced) == payload
            writer, reader = reader, writer

        if "handshake_hash" in vector:
            assert init.handshake_hash == bytes.fromhex(vector["handshake_hash"])
