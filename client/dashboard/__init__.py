# dashboard/__init__.py
"""Web dashboard for runtime command dispatch."""
from dashboard.server import CommandHttpServer, start_server

__all__ = ["CommandHttpServer", "start_server"]
