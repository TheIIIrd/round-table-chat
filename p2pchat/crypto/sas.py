"""Short Authentication String — защита от активного MITM.

Noise_XX доказывает, что у собеседника есть приватный ключ к предъявленному
публичному. Он НЕ доказывает, что это ключ нужного человека: атакующий в
середине проводит два честных хендшейка и ретранслирует переписку. Единственное
лекарство — сравнить по независимому каналу (голосом, лично) значение, которое
у сторон совпадёт только при отсутствии посредника.

Берём его из handshake hash: он вбирает всю стенограмму, включая оба статических
ключа, поэтому у MITM получаются два разных значения — согласовать их он не может.

30 цифр — примерно 99.6 бита. Атака требует подобрать пару ключей, дающую
совпадение SAS, что при таком размере невозможно. Более короткие коды (6 цифр)
допустимы только в протоколах с ограничением числа попыток; у нас его нет.
"""

from __future__ import annotations

from . import primitives as p

GROUPS = 6
DIGITS_PER_GROUP = 5


def sas_code(handshake_hash: bytes, groups: int = GROUPS, digits: int = DIGITS_PER_GROUP) -> str:
    """Возвращает код вида ``48291 07734 ...`` — одинаковый у обеих сторон."""
    if len(handshake_hash) != p.HASHLEN:
        raise ValueError(f"handshake hash должен быть {p.HASHLEN} байт")
    material = p.hash_(b"p2pchat-sas-v1" + handshake_hash)
    value = int.from_bytes(material, "big")
    modulus = 10**digits
    out = []
    for _ in range(groups):
        out.append(str(value % modulus).zfill(digits))
        value //= modulus
    return " ".join(out)


def sas_matches(local: str, spoken: str) -> bool:
    """Сравнение с нормализацией пробелов и постоянным временем.

    Постоянное время здесь скорее гигиена, чем необходимость, но привычка
    сравнивать секретоподобные строки через ``compare_digest`` полезнее, чем
    рассуждения о том, где именно утечка по времени опасна.
    """
    import hmac

    return hmac.compare_digest(_normalize(local), _normalize(spoken))


def _normalize(code: str) -> str:
    return "".join(ch for ch in code if ch.isdigit())
