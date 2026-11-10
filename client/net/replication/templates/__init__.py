# net/replication/templates/__init__.py
"""Collect all RepLayout templates."""
from __future__ import annotations

from net.replication.templates.game_state import TEMPLATES as _game_state_templates
from net.replication.types import RepLayoutTemplate

ALL_TEMPLATES: list[RepLayoutTemplate] = [
    *_game_state_templates
]
