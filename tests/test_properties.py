"""Генеративные тесты: много случайных входов вместо нескольких придуманных.

Примеры проверяют то, о чём автор подумал. Здесь проверяется то, о чём он не
подумал: разборщики обстреливаются мусором, а дурак играется тысячу раз со
случайными раскладами с проверкой инвариантов.

Почему не `hypothesis`. Библиотеки нет в окружении, где писался код, а тест,
который нельзя запустить, — не тест. Генератор здесь простой и **засеянный**:
каждый прогон одинаков, поэтому падение воспроизводится по номеру итерации.
Переход на `hypothesis` был бы улучшением — он умеет сокращать найденный
контрпример, — но заменяет, а не дополняет то, что здесь есть.
"""

from __future__ import annotations

import asyncio
import random

# Тест обращается к внутренностям игры: без этого инварианты не проверить.
# pylint: disable=protected-access

from p2pchat.format import panel, sanitize, strip_ansi, width
from p2pchat.games.cards import CardError, parse_card, resolve_in_hand
from p2pchat.games.durak import Durak
from p2pchat.net.framing import FrameError, read_frame
from p2pchat.proto.envelope import Envelope, EnvelopeError
from p2pchat.proto.files import (
    TransferError,
    decode_chunk,
    decode_offer,
    sanitize_name,
)
from p2pchat.proto.invite import InviteError, decode_group, decode_peer

ITERATIONS = 400


def random_bytes(rng: random.Random, limit: int = 200) -> bytes:
    return bytes(rng.randrange(256) for _ in range(rng.randrange(limit)))


# --- разборщики: на мусоре допустимо только объявленное исключение ---------------


def test_envelope_decode_survives_garbage():
    rng = random.Random(1)
    for step in range(ITERATIONS):
        raw = random_bytes(rng)
        try:
            envelope = Envelope.decode(raw)
        except EnvelopeError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"шаг {step}: неожиданное {type(exc).__name__}: {exc}") from exc
        # Что разобралось — должно кодироваться обратно без потерь.
        assert Envelope.decode(envelope.encode()) == envelope


def test_invite_decode_survives_garbage():
    rng = random.Random(2)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=?!" + "абв"
    for step in range(ITERATIONS):
        body = "".join(rng.choice(alphabet) for _ in range(rng.randrange(120)))
        for prefix in ("p2pchat:", "p2pchat-group:", ""):
            for decode in (decode_peer, decode_group):
                try:
                    decode(prefix + body)
                except InviteError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    raise AssertionError(
                        f"шаг {step}: {decode.__name__} упал с {type(exc).__name__}: {exc}"
                    ) from exc


def test_file_bodies_survive_garbage():
    rng = random.Random(3)
    for step in range(ITERATIONS):
        raw = random_bytes(rng, limit=120)
        for decode in (decode_offer, decode_chunk):
            try:
                decode(raw)
            except TransferError:
                pass
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"шаг {step}: {decode.__name__} упал с {type(exc).__name__}: {exc}"
                ) from exc


def test_card_parsing_survives_garbage():
    rng = random.Random(4)
    alphabet = "0123456789ТВДКtjqka♠♥♦♣пчбтsхd -"
    for step in range(ITERATIONS):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(6)))
        try:
            parse_card(text)
        except CardError:
            pass
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"шаг {step}: parse_card упал с {type(exc).__name__}") from exc
        try:
            resolve_in_hand(text, [])
        except CardError:
            pass
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"шаг {step}: resolve_in_hand упал с {type(exc).__name__}"
            ) from exc


def test_frame_reader_survives_garbage():
    async def scenario():
        rng = random.Random(5)
        for step in range(100):
            reader = asyncio.StreamReader()
            reader.feed_data(random_bytes(rng, limit=80))
            reader.feed_eof()
            try:
                await read_frame(reader)
            except (FrameError, asyncio.IncompleteReadError):
                pass
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(f"шаг {step}: {type(exc).__name__}") from exc

    asyncio.run(scenario())


def test_text_helpers_survive_garbage():
    """Оформление применяется к чужому тексту, значит тоже разборщик."""
    rng = random.Random(6)
    for _ in range(ITERATIONS):
        raw = "".join(chr(rng.randrange(0x2600)) for _ in range(rng.randrange(60)))
        cleaned = sanitize(raw)
        assert "\x1b" not in cleaned
        assert strip_ansi(cleaned) == cleaned
        framed = panel(cleaned or "x")
        widths = {width(line) for line in framed.split("\n")}
        assert len(widths) == 1, "рамка разъехалась"


def test_file_names_are_always_safe():
    rng = random.Random(7)
    alphabet = "abcабв/\\.:*?\"<>| \t\n\x00"
    for _ in range(ITERATIONS):
        raw = "".join(rng.choice(alphabet) for _ in range(rng.randrange(40)))
        name = sanitize_name(raw)
        assert name and "/" not in name and "\\" not in name
        assert not name.startswith(".") and name not in {".", ".."}
        assert not any(char < " " for char in name)


# --- дурак: инварианты на случайных партиях ---------------------------------------


def play_random_game(
    seed: int, players: list[str], leave_chance: float = 0.0
) -> tuple[Durak, int]:
    """Играет партию простейшими автоигроками и возвращает игру и число ходов.

    ``leave_chance`` изредка выводит игрока из партии: уход посреди игры — самый
    неудобный путь в правилах, и именно на нём нашлось, что добор возвращал
    карты тому, кого за столом уже нет.
    """
    rng = random.Random(seed)
    game = Durak(random.Random(seed))
    game.start(players)

    for move in range(2000):
        if game.finished:
            return game, move
        check_conservation(game, seed, move)
        check_turn_order(game, seed, move)

        if leave_chance and len(game._active()) > 2 and rng.random() < leave_chance:
            game.on_leave(rng.choice(game._active()))
            continue

        attacker, defender = game._attacker(), game._defender()
        undefended = [laid for laid, beat in game.table if beat is None]

        if not game.table:
            card = rng.choice(game.hands[attacker])
            game.handle(attacker, "attack", str(card))
        elif undefended:
            beats = [c for c in game.hands[defender] if c.beats(undefended[0], game.trump)]
            if beats and rng.random() < 0.8:
                game.handle(defender, "beat", f"{rng.choice(beats)} {undefended[0]}")
            else:
                game.handle(defender, "take", "")
        else:
            helper = next(
                (p for p in game._active() if p != defender and _can_add(game, p)), None
            )
            if helper is not None and rng.random() < 0.5:
                game.handle(helper, "add", str(_addable(game, helper)[0]))
            else:
                for player in [p for p in game._active() if p != defender]:
                    if not game.finished:
                        game.handle(player, "pass", "")
    raise AssertionError(f"партия {seed} не завершилась за 2000 ходов")


def _addable(game: Durak, player: str) -> list:
    ranks = {laid.rank for laid, _ in game.table}
    ranks |= {beat.rank for _, beat in game.table if beat is not None}
    return [card for card in game.hands[player] if card.rank in ranks]


def _can_add(game: Durak, player: str) -> bool:
    if len(game.table) >= 6:
        return False
    return bool(_addable(game, player))


def check_conservation(game: Durak, seed: int, move: int) -> None:
    """Карты не появляются, не пропадают и не двоятся. Верно всегда."""
    seen = []
    for hand in game.hands.values():
        seen.extend(hand)
    seen.extend(game.deck)
    seen.extend(game.discarded)
    for laid, beat in game.table:
        seen.append(laid)
        if beat is not None:
            seen.append(beat)

    where = f"партия {seed}, ход {move}"
    assert len(seen) == 36, f"{where}: карт стало {len(seen)}"
    assert len(set(seen)) == 36, f"{where}: карта в двух местах одновременно"
    # Заманчиво было записать «рука не больше шести», но это неверно: игрок,
    # забравший карты, законно держит больше.
    for player in game.out:
        assert not game.hands[player], f"{where}: у выбывшего {player} остались карты"


def check_turn_order(game: Durak, seed: int, move: int) -> None:
    """Свойства очерёдности. После конца партии указатели ходов уже не значат
    ничего, поэтому проверяются только по ходу игры."""
    where = f"партия {seed}, ход {move}"
    assert game._attacker() != game._defender(), f"{where}: ходит сам на себя"
    assert game._attacker() not in game.out, f"{where}: ходит выбывший"
    assert game._defender() not in game.out, f"{where}: отбивается выбывший"
    assert len(game.table) <= 6, f"{where}: на столе больше шести карт"


def test_random_durak_games_keep_invariants():
    """Тысяча партий: карты не появляются, не пропадают и не двоятся."""
    for seed in range(250):
        for players in (["a", "b"], ["a", "b", "c"], ["a", "b", "c", "d"]):
            game, moves = play_random_game(seed, list(players))
            assert game.finished
            assert moves > 0
            check_conservation(game, seed, moves)


def test_random_games_survive_players_leaving():
    """То же, но участники изредка уходят посреди партии."""
    for seed in range(120):
        for players in (["a", "b", "c"], ["a", "b", "c", "d"]):
            game, _ = play_random_game(seed, list(players), leave_chance=0.03)
            assert game.finished
            check_conservation(game, seed, -1)


def test_random_games_always_name_a_loser_or_draw():
    for seed in range(50):
        game, _ = play_random_game(seed, ["a", "b"])
        remaining = [p for p in game.order if p not in game.out]
        assert len(remaining) <= 1, "в конце партии не может остаться двое с картами"


def test_leaving_player_takes_no_cards_with_them():
    """Карты ушедшего должны уходить в отбой, а не оставаться «на руках».

    Иначе колода сходится по счёту, но состояние врёт: выбывший держит карты,
    которых никто не может сыграть.
    """
    rng = random.Random(11)
    for seed in range(60):
        game = Durak(random.Random(seed))
        players = ["a", "b", "c"]
        game.start(players)
        for _ in range(rng.randrange(1, 6)):
            if game.finished:
                break
            attacker = game._attacker()
            game.handle(attacker, "attack", str(game.hands[attacker][0]))
            defender = game._defender()
            game.handle(defender, "take", "")

        leaver = next(p for p in game._active())
        game.on_leave(leaver)
        check_conservation(game, seed, -1)
        assert not game.hands[leaver], f"партия {seed}: ушедший унёс карты"


def test_tabs_do_not_break_frames():
    """Табуляция не опасна, но её ширину нельзя посчитать заранее."""
    rng = random.Random(12)
    for _ in range(100):
        raw = "".join(rng.choice("абв\t xy\n") for _ in range(rng.randrange(40)))
        cleaned = sanitize(raw)
        assert "\t" not in cleaned
        framed = panel(cleaned or "x")
        assert len({width(line) for line in framed.split("\n")}) == 1
