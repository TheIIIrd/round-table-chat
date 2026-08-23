"""Тесты игрового каркаса: лобби, таймауты, реконнект и правила игры."""

# Тест проверяет в том числе внутреннее состояние — иначе половину
# свойств безопасности не подтвердить. Импорты внутри функций держат
# сценарии самодостаточными.
# pylint: disable=protected-access

from __future__ import annotations

from random import Random

from p2pchat.games import build_host
from p2pchat.games.api import Finish, Whisper
from p2pchat.games.connect_four import COLUMNS, TURN_TIMEOUT, ConnectFour
from p2pchat.games.lobby import GameHost, Phase


def host() -> GameHost:
    return build_host(Random(1234))


def texts(actions) -> str:
    parts = []
    for action in actions:
        parts.append(getattr(action, "text", None) or getattr(action, "summary", ""))
    return "\n".join(parts)


def started() -> tuple[GameHost, list[str]]:
    h = host()
    h.dispatch("alice", "game", "c4")
    h.dispatch("bob", "join", "")
    h.dispatch("alice", "start", "")
    return h, list(h.players)


def play(h: GameHost, columns: list[int]):
    """Ходит тот, чья очередь: тесты не должны знать порядок после тасовки."""
    last = []
    for column in columns:
        last = h.dispatch(h.players[h.game.turn], "drop", str(column))
    return last


# --- лобби --------------------------------------------------------------------


def test_catalog_is_listed():
    assert "c4" in texts(host().dispatch("alice", "game", ""))


def test_unknown_game_is_reported():
    assert "неизвестна" in texts(host().dispatch("alice", "game", "квиддич"))


def test_gathering_and_start():
    h = host()
    assert "собирает игру" in texts(h.dispatch("alice", "game", "c4"))
    assert h.phase is Phase.GATHERING
    assert "bob в игре" in texts(h.dispatch("bob", "join", ""))
    assert "началась" in texts(h.dispatch("alice", "start", ""))
    assert h.phase is Phase.RUNNING


def test_start_refused_without_enough_players():
    h = host()
    h.dispatch("alice", "game", "c4")
    assert "хотя бы 2" in texts(h.dispatch("alice", "start", ""))
    assert h.phase is Phase.GATHERING


def test_third_player_gets_no_seat():
    h = host()
    h.dispatch("alice", "game", "c4")
    h.dispatch("bob", "join", "")
    assert "Мест нет" in texts(h.dispatch("carol", "join", ""))


def test_second_game_refused_while_one_runs():
    h, _ = started()
    assert "уже идёт" in texts(h.dispatch("carol", "game", "c4"))


def test_leaving_lobby_cancels_when_empty():
    h = host()
    h.dispatch("alice", "game", "c4")
    assert "Сбор отменён" in texts(h.dispatch("alice", "leave", ""))
    assert h.phase is Phase.IDLE


def test_stop_only_by_participant():
    h, _ = started()
    assert "только участник" in texts(h.dispatch("carol", "stop", ""))
    assert "прервал" in texts(h.dispatch("alice", "stop", ""))
    assert h.phase is Phase.IDLE


def test_gathering_expires():
    h = host()
    h.dispatch("alice", "game", "c4", now=0.0)
    assert h.tick(now=10.0) == []
    assert "отменён" in texts(h.tick(now=h.gather_timeout + 1))
    assert h.phase is Phase.IDLE


def test_outsider_cannot_move():
    h, _ = started()
    assert "не участвуете" in texts(h.dispatch("carol", "drop", "1"))


def test_verbs_are_routed_only_when_known():
    h = host()
    assert h.owns("join") is True
    assert h.owns("drop") is False  # игра ещё не идёт
    h.dispatch("alice", "game", "c4")
    h.dispatch("bob", "join", "")
    h.dispatch("alice", "start", "")
    assert h.owns("drop") is True
    assert h.owns("roll") is False  # это команда бота, не игры


# --- правила Connect Four -----------------------------------------------------


def test_win_is_detected_horizontally():
    h, _ = started()
    first = h.players[0]
    result = play(h, [1, 1, 2, 2, 3, 3, 4])
    assert any(isinstance(action, Finish) for action in result)
    assert first in texts(result) and "четыре в ряд" in texts(result)
    assert h.phase is Phase.IDLE  # место освободилось само


def test_win_is_detected_diagonally():
    """Лесенка: сторона 0 занимает диагональ, сторона 1 подкладывает основание."""
    game = ConnectFour(Random(0))
    game.start(("alice", "bob"))
    bottom = len(game.board) - 1
    for column in range(4):
        for filler in range(column):  # подпорки под диагональ
            game.board[bottom - filler][column] = 1
        game.board[bottom - column][column] = 0

    assert game._wins(bottom - 3, 3, 0) is True
    # У подпорок четвёрки нет: их всего три в нижнем ряду.
    assert game._wins(bottom, 1, 1) is False


def test_vertical_win():
    h, _ = started()
    result = play(h, [1, 2, 1, 2, 1, 2, 1])
    assert "четыре в ряд" in texts(result)


def test_invalid_moves_are_private_and_harmless():
    h, _ = started()
    mover = h.players[h.game.turn]
    for bad in ("", "0", "8", "восемь", "-1"):
        actions = h.dispatch(mover, "drop", bad)
        assert all(isinstance(action, Whisper) for action in actions)
    assert h.game.moves == 0


def test_out_of_turn_move_rejected():
    h, _ = started()
    waiting = h.players[1 - h.game.turn]
    assert "сейчас ходит" in texts(h.dispatch(waiting, "drop", "1"))


def test_full_column_rejected():
    h, _ = started()
    play(h, [1] * 6)
    mover = h.players[h.game.turn]
    assert "заполнен" in texts(h.dispatch(mover, "drop", "1"))


def test_draw_when_board_fills():
    """Заполняем доску, каждый раз выбирая ход, не создающий четвёрку.

    Ничья в Connect Four достижима, но подобрать её вручную трудно, поэтому
    ходы выбираются жадно. Если безопасного хода не осталось, партия закончится
    победой — тест принимает оба исхода, но требует, чтобы игра корректно
    завершилась сама, а не зависла с полной доской.
    """
    game = ConnectFour(Random(0))
    game.start(("alice", "bob"))

    result: list = []
    for _ in range(COLUMNS * len(game.board)):
        column = _next_draw_column(game)
        result = game.handle(game.players[game.turn], "drop", str(column + 1))
        if any(isinstance(action, Finish) for action in result):
            break

    assert any(isinstance(action, Finish) for action in result)
    assert game.finished is True


def test_board_command_is_private():
    h, _ = started()
    actions = h.dispatch("bob", "board", "")
    assert len(actions) == 1 and isinstance(actions[0], Whisper)


def test_leaving_mid_game_awards_win():
    h, _ = started()
    quitter = h.players[0]
    winner = h.players[1]
    result = h.on_peer_lost(quitter)
    assert winner in texts(result)
    assert h.phase is Phase.IDLE


def test_turn_timeout_ends_game():
    h, _ = started()
    assert h.tick(now=1.0) == []
    warning = h.tick(now=h.game.deadline - 10)
    assert "осталось" in texts(warning)
    assert texts(h.tick(now=h.game.deadline + 1)).count("не сходил вовремя") == 1
    assert h.phase is Phase.IDLE


def test_timeout_warning_fires_once():
    h, _ = started()
    h.tick(now=h.game.deadline - 10)
    assert h.tick(now=h.game.deadline - 9) == []


def test_reconnect_restores_private_state():
    h, _ = started()
    play(h, [3])
    returning = h.players[0]

    actions = h.on_peer_back(returning)
    assert len(actions) == 1 and isinstance(actions[0], Whisper)
    body = actions[0].text
    assert "Вы играете" in body and "ходит" in body

    assert h.on_peer_back("carol") == []  # не участник — нечего восстанавливать


def test_snapshot_before_start_is_empty():
    assert ConnectFour(Random(0)).snapshot_for("alice") == ""


def test_timeout_length_is_sane():
    assert 30 <= TURN_TIMEOUT <= 600


# --- вспомогательное ----------------------------------------------------------


def _row_for(game: ConnectFour, column: int) -> int:
    for row in range(len(game.board) - 1, -1, -1):
        if game.board[row][column] is None:
            return row
    raise AssertionError("столбец полон")


def _next_draw_column(game: ConnectFour) -> int:
    """Любой столбец, ход в который не создаёт четвёрку; иначе первый свободный."""
    free = [c for c in range(COLUMNS) if game.board[0][c] is None]
    for column in free:
        row = _row_for(game, column)
        game.board[row][column] = game.turn
        wins = game._wins(row, column, game.turn)
        game.board[row][column] = None
        if not wins:
            return column
    return free[0]
