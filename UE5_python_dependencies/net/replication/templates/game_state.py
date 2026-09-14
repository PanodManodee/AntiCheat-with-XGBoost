# net/replication/templates/game_state.py
"""GameState template — server time sync callback."""
from __future__ import annotations

import time
from typing import Any

from net.replication.types import RepLayoutTemplate
from net.state.game_state import get_game_state


def _on_update(props: dict, connection: Any) -> None:
    t = props.get('ReplicatedWorldTimeSecondsDouble')
    if t is not None and connection is not None:
        get_game_state(connection).update_server_time(t, time.time())


TEMPLATES = [
    RepLayoutTemplate(
        match=lambda n: 'GameState' in n,
        on_update=_on_update,
    ),
]