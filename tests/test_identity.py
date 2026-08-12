"""Тесты долговременной идентичности и файла ключа."""

from __future__ import annotations

import stat

import pytest

from p2pchat.crypto import identity as ident
from p2pchat.crypto.identity import Identity, KeyFileError

# Argon2id с боевыми параметрами занимает сотни миллисекунд — в тестах это
# превращается в минуты. Снижаем стоимость только для тестов.
@pytest.fixture(autouse=True)
def cheap_kdf(monkeypatch):
    monkeypatch.setattr(ident, "ARGON2_MEMORY_KIB", 8 * 1024)
    monkeypatch.setattr(ident, "ARGON2_TIME_COST", 1)


def test_save_load_roundtrip(tmp_path):
    original = Identity.generate(nickname="alice")
    path = tmp_path / "id.key"
    original.save(path, "правильная лошадь батарейка скрепка")

    loaded = Identity.load(path, "правильная лошадь батарейка скрепка")
    assert loaded.public == original.public
    assert loaded.keypair.private_bytes() == original.keypair.private_bytes()


def test_wrong_passphrase_rejected(tmp_path):
    path = tmp_path / "id.key"
    Identity.generate().save(path, "верная")
    with pytest.raises(KeyFileError):
        Identity.load(path, "неверная")


def test_private_key_not_on_disk_in_clear(tmp_path):
    path = tmp_path / "id.key"
    identity = Identity.generate()
    identity.save(path, "пассфраза")
    blob = path.read_bytes()
    assert identity.keypair.private_bytes() not in blob
    assert identity.public not in blob


def test_file_permissions_are_owner_only(tmp_path):
    path = tmp_path / "id.key"
    Identity.generate().save(path, "пассфраза")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_tampered_header_rejected(tmp_path):
    """Понижение параметров Argon2 ломает тег: заголовок в associated data."""
    path = tmp_path / "id.key"
    Identity.generate().save(path, "пассфраза")
    raw = bytearray(path.read_bytes())
    idx = len(ident.MAGIC) + 1  # байт t_cost
    raw[idx] = raw[idx] + 1  # заведомо другое, но валидное значение
    path.write_bytes(bytes(raw))
    with pytest.raises(KeyFileError):
        Identity.load(path, "пассфраза")


def test_alien_file_rejected(tmp_path):
    path = tmp_path / "id.key"
    path.write_bytes(b"x" * 100)
    with pytest.raises(KeyFileError):
        Identity.load(path, "пассфраза")


def test_empty_passphrase_refused(tmp_path):
    with pytest.raises(ValueError):
        Identity.generate().save(tmp_path / "id.key", "")


def test_fingerprint_is_stable_and_distinct():
    a, b = Identity.generate(), Identity.generate()
    assert a.fingerprint() == a.fingerprint()
    assert a.fingerprint() != b.fingerprint()
    assert len(a.fingerprint().replace(" ", "")) == 32
