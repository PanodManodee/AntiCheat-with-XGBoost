# net/packets/control/closereason.py
"""CloseReason - Server sends reason for closing connection."""
from __future__ import annotations

from net.packets.in_bunch import FInBunch


class CloseReason:
    @staticmethod
    def Received(conn, bunch: FInBunch) -> str:
        reason = bunch.read_fstring()
        print(f"[CloseReason] Server: {reason}")
        return reason
