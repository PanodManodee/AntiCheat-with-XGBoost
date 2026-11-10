# net/packets/control/failure.py
from __future__ import annotations
from net.packets.in_bunch import FInBunch


class Failure:
    @staticmethod
    def Received(conn, bunch: FInBunch) -> str:
        reason = bunch.read_fstring()
        print(f"[Failure] Server: {reason}")
        return reason
