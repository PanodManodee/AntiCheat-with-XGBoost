# net/state/__init__.py
from __future__ import annotations

from typing import Any, TypeVar

from net.state.game_state import GameState, get_game_state
from net.state.session_state import SessionState, get_session_state

__all__ = [
    "GameState",
    "SessionState",
    "get_game_state",
    "get_session_state",
]

T = TypeVar("T")


def get_connection_state(connection: Any, key: str, factory: type[T]) -> T:
    """Retrieve or lazily create per-connection extension state."""
    getter = getattr(connection, "get_extension", None)
    if callable(getter):
        return getter(key, factory)

    extensions = getattr(connection, "extensions", None)
    if extensions is None:
        extensions = {}
        setattr(connection, "extensions", extensions)

    state = extensions.get(key)
    if state is None:
        state = factory()
        extensions[key] = state
    return state
