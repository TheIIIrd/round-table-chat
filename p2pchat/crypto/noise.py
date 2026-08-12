"""CipherState и SymmetricState — разделы 5.1 и 5.2 спецификации Noise (rev 34).

Здесь нет ничего специфичного для паттерна XX: эти два объекта одинаковы для
любого хендшейка Noise. Разделение сделано ради тестируемости — состояния
шифра проверяются отдельно от логики обмена сообщениями.
"""

from __future__ import annotations

from . import primitives as p

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2s"


class NoiseError(Exception):
    """Нарушение протокола: исчерпан nonce, некорректная длина сообщения и т. п."""


class CipherState:
    """Симметричный ключ плюс счётчик сообщений.

    Пустой ключ (``k is None``) означает, что шифрование ещё не включено —
    в этом режиме данные проходят насквозь, как того требует спецификация.
    """

    __slots__ = ("k", "n")

    def __init__(self, key: bytes | None = None) -> None:
        self.initialize_key(key)

    def initialize_key(self, key: bytes | None) -> None:
        if key is not None and len(key) != p.KEYLEN:
            raise ValueError(f"ключ должен быть {p.KEYLEN} байт")
        self.k = key
        self.n = 0

    def has_key(self) -> bool:
        return self.k is not None

    def set_nonce(self, nonce: int) -> None:
        self.n = nonce

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        if self.n >= p.MAX_NONCE:
            raise NoiseError("исчерпан счётчик nonce — требуется новый хендшейк")
        ct = p.encrypt(self.k, self.n, ad, plaintext)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        if self.n >= p.MAX_NONCE:
            raise NoiseError("исчерпан счётчик nonce — требуется новый хендшейк")
        pt = p.decrypt(self.k, self.n, ad, ciphertext)
        # Счётчик двигаем только после успешной проверки тега: иначе одно
        # подделанное сообщение рассинхронизировало бы стороны навсегда.
        self.n += 1
        return pt

    def rekey(self) -> None:
        """Прокрутка ключа (раздел 11.3).

        Даёт forward secrecy, но НЕ post-compromise security: обладатель
        текущего ключа может прокручивать его дальше самостоятельно. Для PCS
        нужен свежий обмен эфемерными ключами — это делается уровнем выше.
        """
        if self.k is None:
            raise NoiseError("нечего прокручивать: ключ не установлен")
        self.k = p.encrypt(self.k, p.MAX_NONCE, b"", bytes(p.KEYLEN))[: p.KEYLEN]


class SymmetricState:
    """Состояние, накапливающее хеш стенограммы (``h``) и цепочку ключей (``ck``)."""

    __slots__ = ("cipher_state", "ck", "h")

    def __init__(self, protocol_name: bytes = PROTOCOL_NAME) -> None:
        if len(protocol_name) <= p.HASHLEN:
            self.h = protocol_name + bytes(p.HASHLEN - len(protocol_name))
        else:
            self.h = p.hash_(protocol_name)
        self.ck = self.h
        self.cipher_state = CipherState()

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = p.hkdf(self.ck, input_key_material, 2)
        self.cipher_state.initialize_key(temp_k)

    def mix_hash(self, data: bytes) -> None:
        self.h = p.hash_(self.h + data)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        temp_k1, temp_k2 = p.hkdf(self.ck, b"", 2)
        return CipherState(temp_k1), CipherState(temp_k2)
