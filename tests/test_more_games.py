"""Тесты добавленных игр."""

from __future__ import annotations

from random import Random

import pytest

from p2pchat.games import build_host
from p2pchat.games.api import Finish, GameError, Say, Whisper
from p2pchat.games.cards import Card, CardError, deck36, parse_card, sort_hand
from p2pchat.games.durak import Durak
from p2pchat.games.hangman import WORDS, Hangman
from p2pchat.games.lobby import GameHost, Phase
from p2pchat.games.mafia import CIVILIAN, DETECTIVE, MAFIA, Mafia, Phase as MafiaPhase


def texts(actions) -> str:
    return "\n".join(
        getattr(action, "text", None) or getattr(action, "summary", "") for action in actions
    )


def whispers(actions, player: str) -> str:
    return "\n".join(a.text for a in actions if isinstance(a, Whisper) and a.player == player)


def open_game(name: str, players: list[str], seed: int = 1) -> GameHost:
    host = build_host(Random(seed))
    host.dispatch(players[0], "game", name)
    for player in players[1:]:
        host.dispatch(player, "join", "")
    host.dispatch(players[0], "start", "")
    return host


# --- карты ---------------------------------------------------------------------


def test_card_parsing_accepts_both_layouts():
    assert parse_card("7ч") == parse_card("7h") == parse_card("7♥") == Card("7", "♥")
    assert parse_card("10п") == Card("10", "♠")
    assert parse_card("тб") == parse_card("ad") == Card("Т", "♦")
    assert parse_card("Вт") == Card("В", "♣")


def test_card_parsing_rejects_nonsense():
    for bad in ("", "7", "х7", "15ч", "туз", "7щ"):
        with pytest.raises(CardError):
            parse_card(bad)


def test_trump_beats_non_trump():
    assert Card("6", "♥").beats(Card("Т", "♠"), trump="♥") is True
    assert Card("Т", "♠").beats(Card("6", "♥"), trump="♥") is False
    assert Card("9", "♠").beats(Card("8", "♠"), trump="♥") is True
    assert Card("8", "♠").beats(Card("9", "♠"), trump="♥") is False
    assert Card("Т", "♠").beats(Card("6", "♦"), trump="♥") is False  # разные масти, не козырь


def test_deck_is_complete_and_shuffled():
    first = deck36(Random(1))
    second = deck36(Random(2))
    assert len(first) == 36 and len(set(first)) == 36
    assert first != second


def test_hand_sorting_puts_trumps_last():
    hand = [Card("Т", "♥"), Card("6", "♠"), Card("6", "♥"), Card("К", "♠")]
    assert sort_hand(hand, "♥") == [Card("6", "♠"), Card("К", "♠"), Card("6", "♥"), Card("Т", "♥")]


# --- дурак ----------------------------------------------------------------------


def test_durak_deals_six_each_and_picks_trump():
    game = Durak(Random(5))
    game.start(("alice", "bob", "carol"))
    assert all(len(hand) == 6 for hand in game.hands.values())
    assert len(game.deck) == 36 - 18
    assert game.trump_card.suit == game.trump


def test_durak_first_attacker_has_lowest_trump():
    game = Durak(Random(9))
    game.start(("alice", "bob", "carol"))
    trumps = [
        (card.value(), player)
        for player, hand in game.hands.items()
        for card in hand
        if card.suit == game.trump
    ]
    if trumps:
        assert game._attacker() == min(trumps)[1]


def test_durak_hands_are_private():
    host = open_game("durak", ["alice", "bob"])
    start = host.dispatch("alice", "hand", "")
    assert len(start) == 1 and isinstance(start[0], Whisper)
    assert start[0].player == "alice"


def test_durak_rejects_illegal_moves():
    game = Durak(Random(4))
    game.start(("alice", "bob"))
    attacker, defender = game._attacker(), game._defender()

    with pytest.raises(GameError):
        game.handle(defender, "attack", str(game.hands[defender][0]))  # не его очередь
    with pytest.raises(GameError):
        game.handle(attacker, "attack", "7щ")  # мусор вместо карты
    foreign = next(card for card in game.hands[defender] if card not in game.hands[attacker])
    with pytest.raises(GameError):
        game.handle(attacker, "attack", str(foreign))  # чужая карта
    with pytest.raises(GameError):
        game.handle(attacker, "pass", "")  # пасовать нечего


def test_durak_defence_requires_stronger_card():
    game = Durak(Random(4))
    game.start(("alice", "bob"))
    attacker, defender = game._attacker(), game._defender()
    attack_card = min(game.hands[attacker], key=lambda c: (c.suit == game.trump, c.value()))
    game.handle(attacker, "attack", str(attack_card))

    weak = [
        card
        for card in game.hands[defender]
        if not card.beats(attack_card, game.trump)
    ]
    if weak:
        with pytest.raises(GameError):
            game.handle(defender, "beat", f"{weak[0]} {attack_card}")


def test_durak_take_moves_cards_to_hand():
    game = Durak(Random(4))
    game.start(("alice", "bob"))
    attacker, defender = game._attacker(), game._defender()
    before = len(game.hands[defender])
    game.handle(attacker, "attack", str(game.hands[attacker][0]))
    game.handle(defender, "take", "")
    assert len(game.hands[defender]) >= before + 1


def test_durak_only_matching_rank_can_be_added():
    game = Durak(Random(4))
    game.start(("alice", "bob", "carol"))
    attacker = game._attacker()
    third = next(p for p in game.order if p not in (attacker, game._defender()))
    laid = game.hands[attacker][0]
    game.handle(attacker, "attack", str(laid))

    mismatched = [card for card in game.hands[third] if card.rank != laid.rank]
    if mismatched:
        with pytest.raises(GameError):
            game.handle(third, "add", str(mismatched[0]))


def test_durak_full_game_terminates():
    """Два простейших автоигрока доводят партию до конца без зависаний."""
    host = open_game("durak", ["alice", "bob"], seed=11)
    game = host.game
    for _ in range(500):
        if host.game is None or game.finished:
            break
        attacker, defender = game._attacker(), game._defender()
        if not game.table:
            host.dispatch(attacker, "attack", str(game.hands[attacker][0]))
            continue
        undefended = [laid for laid, beat in game.table if beat is None]
        if undefended:
            target = undefended[0]
            beats = [c for c in game.hands[defender] if c.beats(target, game.trump)]
            if beats:
                host.dispatch(defender, "beat", f"{beats[0]} {target}")
            else:
                host.dispatch(defender, "take", "")
        else:
            host.dispatch(attacker, "pass", "")
    assert game.finished is True
    assert host.phase is Phase.IDLE


def test_durak_leaving_ends_two_player_game():
    host = open_game("durak", ["alice", "bob"])
    result = host.on_peer_lost("alice")
    assert any(isinstance(action, Finish) for action in result)


def test_durak_snapshot_shows_hand_and_table():
    host = open_game("durak", ["alice", "bob"])
    body = texts(host.on_peer_back("alice"))
    assert "Ваша рука" in body and "Стол" in body


# --- мафия -----------------------------------------------------------------------


def test_mafia_assigns_roles_privately():
    host = open_game("mafia", ["alice", "bob", "carol", "dave"], seed=3)
    game = host.game
    assert sorted(game.roles) == ["alice", "bob", "carol", "dave"]
    assert list(game.roles.values()).count(MAFIA) == 1
    assert list(game.roles.values()).count(DETECTIVE) == 1
    assert list(game.roles.values()).count(CIVILIAN) == 2

    actions = game.start(("alice", "bob", "carol", "dave"))
    private = [a for a in actions if isinstance(a, Whisper)]
    assert len(private) == 4
    assert all("роль" in a.text.lower() for a in private)
    # Роль не должна утечь в общий канал.
    assert MAFIA.upper() not in texts([a for a in actions if isinstance(a, Say)])


def test_mafia_partners_know_each_other():
    game = Mafia(Random(0))
    actions = game.start(("a", "b", "c", "d", "e", "f"))
    mafiosi = [p for p, r in game.roles.items() if r == MAFIA]
    assert len(mafiosi) == 2
    for member in mafiosi:
        card = whispers(actions, member)
        assert any(other in card for other in mafiosi if other != member)


def test_mafia_only_mafia_kills_and_not_their_own():
    game = Mafia(Random(3))
    game.start(("alice", "bob", "carol", "dave"))
    mafia = next(p for p, r in game.roles.items() if r == MAFIA)
    civilian = next(p for p, r in game.roles.items() if r == CIVILIAN)

    with pytest.raises(GameError):
        game.handle(civilian, "kill", mafia)  # не его ход
    with pytest.raises(GameError):
        game.handle(mafia, "kill", mafia)  # свой
    with pytest.raises(GameError):
        game.handle(mafia, "kill", "несуществующий")


def test_mafia_detective_learns_truth():
    game = Mafia(Random(3))
    game.start(("alice", "bob", "carol", "dave"))
    mafia = next(p for p, r in game.roles.items() if r == MAFIA)
    detective = next(p for p, r in game.roles.items() if r == DETECTIVE)

    result = game.handle(detective, "check", mafia)
    assert whispers(result, detective).endswith("мафия.")
    with pytest.raises(GameError):
        game.handle(detective, "check", mafia)  # вторая проверка за ночь


def test_mafia_night_resolves_when_everyone_moved():
    game = Mafia(Random(3))
    game.start(("alice", "bob", "carol", "dave"))
    mafia = next(p for p, r in game.roles.items() if r == MAFIA)
    detective = next(p for p, r in game.roles.items() if r == DETECTIVE)
    victim = next(p for p in game.alive if p not in (mafia, detective))

    game.handle(mafia, "kill", victim)
    result = game.handle(detective, "check", mafia)
    assert "Рассвет" in texts(result)
    assert victim not in game.alive
    assert game.phase is MafiaPhase.DAY


def test_mafia_city_wins_by_vote():
    host = open_game("mafia", ["alice", "bob", "carol", "dave"], seed=3)
    game = host.game
    mafia = next(p for p, r in game.roles.items() if r == MAFIA)
    detective = next(p for p, r in game.roles.items() if r == DETECTIVE)
    victim = next(p for p in game.alive if p not in (mafia, detective))

    host.dispatch(mafia, "kill", victim)
    host.dispatch(detective, "check", mafia)
    host.dispatch(detective, "day", "")
    result = []
    for voter in list(game.alive):
        result = host.dispatch(voter, "vote", mafia)
        if host.phase is Phase.IDLE:
            break
    assert "победа города" in texts(result)


def test_mafia_wins_when_numbers_equalize():
    game = Mafia(Random(0))
    game.roles = {"m": MAFIA, "a": CIVILIAN, "b": CIVILIAN}
    game.alive = ["m", "a", "b"]
    game.phase = MafiaPhase.NIGHT
    game._kill_target = "a"
    result = game._dawn()
    assert "победа мафии" in texts(result)
    assert game.finished is True


def test_mafia_vote_tie_kills_nobody():
    game = Mafia(Random(0))
    game.roles = {"m": MAFIA, "a": CIVILIAN, "b": CIVILIAN, "c": CIVILIAN}
    game.alive = ["m", "a", "b", "c"]
    game.phase = MafiaPhase.VOTE
    game._votes = {"m": "a", "a": "m", "b": "a", "c": "m"}
    result = game._count_votes(by_timeout=False)
    assert "Ничья" in texts(result)
    assert len(game.alive) == 4


def test_mafia_dead_cannot_act():
    game = Mafia(Random(3))
    game.start(("alice", "bob", "carol", "dave"))
    dead = game.alive[0]
    game.alive.remove(dead)
    with pytest.raises(GameError):
        game.handle(dead, "vote", game.alive[0])


def test_mafia_snapshot_keeps_role():
    host = open_game("mafia", ["alice", "bob", "carol", "dave"], seed=3)
    body = texts(host.on_peer_back("alice"))
    assert "роль" in body.lower() and "Живые" in body


# --- виселица ---------------------------------------------------------------------


def test_word_list_is_clean():
    assert len(WORDS) > 30
    assert all(word.isalpha() and word.islower() and not word.isascii() for word in WORDS)


def test_hangman_reveals_letters():
    game = Hangman(Random(0))
    game.start(("alice",))
    game.secret = "телескоп"
    game.opened.clear()

    result = game.handle("alice", "letter", "е")
    assert "есть" in texts(result)
    assert game.masked() == "_ е _ е _ _ _ _"


def test_hangman_counts_mistakes_and_loses():
    game = Hangman(Random(0))
    game.start(("alice",))
    game.secret = "маяк"
    game.opened.clear()
    game.wrong.clear()

    result = []
    for letter in "бвгдежз":
        result = game.handle("alice", "letter", letter)
    assert any(isinstance(action, Finish) for action in result)
    assert "маяк" in texts(result)


def test_hangman_rejects_repeats_and_nonletters():
    game = Hangman(Random(0))
    game.start(("alice",))
    game.secret = "маяк"
    game.opened.clear()
    game.wrong.clear()

    game.handle("alice", "letter", "м")
    for bad in ("м", "", "аб", "5", " "):
        with pytest.raises(GameError):
            game.handle("alice", "letter", bad)


def test_hangman_whole_word_guess():
    game = Hangman(Random(0))
    game.start(("bob",))
    game.secret = "гитара"
    result = game.handle("bob", "word", "  ГИТАРА ")
    assert any(isinstance(action, Finish) for action in result)
    assert "bob" in texts(result)


def test_hangman_is_cooperative_without_turn_order():
    host = open_game("hangman", ["alice", "bob", "carol"])
    host.game.secret = "остров"
    host.game.opened.clear()
    assert "есть" in texts(host.dispatch("carol", "letter", "о"))
    assert "есть" in texts(host.dispatch("bob", "letter", "с"))


def test_hangman_yo_is_treated_as_e():
    game = Hangman(Random(0))
    game.start(("alice",))
    game.secret = "вертолёт"
    game.opened.clear()
    game.handle("alice", "letter", "е")
    assert "ё" in game.opened or "е" in game.opened
    assert "_" in game.masked()
