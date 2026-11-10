# net/state/game_state.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


GAME_STATE_KEY = "game"


@dataclass(slots=True)
class GameState:
    server_time_seconds: float = 0.0
    server_time_local_ts: float = 0.0

    def update_server_time(self, seconds: float, local_ts: float) -> None:
        self.server_time_seconds = seconds
        self.server_time_local_ts = local_ts


def get_game_state(connection: Any) -> GameState:
    from net.state import get_connection_state
    return get_connection_state(connection, GAME_STATE_KEY, GameState)
