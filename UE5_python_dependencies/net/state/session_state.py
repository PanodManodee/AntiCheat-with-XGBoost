# net/state/session_state.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SESSION_STATE_KEY = "session"


@dataclass(slots=True)
class SessionState:
    eos_id_token: str = ""
    steam_ticket_b64: str = ""
    player_id: str = ""
    login_params: dict[str, Any] | None = None


def get_session_state(connection: Any) -> SessionState:
    from net.state import get_connection_state
    return get_connection_state(connection, SESSION_STATE_KEY, SessionState)
