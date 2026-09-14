# net/packets/control/join.py
from __future__ import annotations
from net.packets.in_bunch import FInBunch
from net.packets.out_bunch import FOutBunch
from net.packets.control import NetControlMessageType
from core.names.ename import EName


class Join:
    @staticmethod
    def Get(conn) -> bytes:
        send_buffer = conn.init_send_buffer(500)

        bunch = FOutBunch(conn.max_bunch_payload_bits)
        bunch.bReliable = True
        bunch.ChNameIndex = EName.Control

        bunch.serialize(bytes([NetControlMessageType.Join]))

        return conn.get_raw_bunch(bunch, send_buffer)

    @staticmethod
    def Received(conn, bunch: FInBunch) -> None:
        pass  # NMT_Join has no parameters in UE5 5.7
