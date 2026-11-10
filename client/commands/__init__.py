# commands/__init__.py
"""Command subsystem — auto-registers all built-in command modules."""
from commands.base import CommandContext, dispatch, drain_commands, tick_all

# Import sub-modules to trigger command registration
from commands import move, nick

__all__ = ["CommandContext", "dispatch", "drain_commands", "tick_all"]
