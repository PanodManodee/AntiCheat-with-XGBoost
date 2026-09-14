# net/packets/control/netspeed.py
from __future__ import annotations
from net.packets.in_bunch import FInBunch
from net.packets.out_bunch import FOutBunch
from net.packets.control import NetControlMessageType
from core.names.ename import EName


class Netspeed:
    @staticmethod
    def Get(conn, NetSpeed: int = 1200000) -> bytes:
        send_buffer = conn.init_send_buffer(500)

        bunch = FOutBunch(conn.max_bunch_payload_bits)
        bunch.bReliable = True
        bunch.ChNameIndex = EName.Control

        bunch.serialize(bytes([NetControlMessageType.Netspeed]))
        bunch.write_uint32(NetSpeed)

        return conn.get_raw_bunch(bunch, send_buffer)

    @staticmethod
    def Received(conn, bunch: FInBunch) -> None:
        bunch.read_uint32()  # NetSpeed
