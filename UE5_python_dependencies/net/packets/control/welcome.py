# net/packets/control/welcome.py
from __future__ import annotations
from net.packets.in_bunch import FInBunch


class Welcome:
    @staticmethod
    def Received(conn, bunch: FInBunch) -> None:
        bunch.read_fstring()  # levelName
        bunch.read_fstring()  # gameName
        bunch.read_fstring()  # redirectUrl
