# net/packets/control/hello.py
from __future__ import annotations
from net.packets.out_bunch import FOutBunch
from net.packets.in_bunch import FInBunch
from net.packets.control import NetControlMessageType
from core.names.ename import EName


class Hello:
    @staticmethod
    def Get(conn, EncryptionToken: str = "", RuntimeFeatures: int = 0) -> bytes:
        send_buffer = conn.init_send_buffer(clock_time_ms=1023)

        bunch = FOutBunch(conn.max_bunch_payload_bits)
        bunch.bOpen = True
        bunch.bReliable = True
        bunch.ChIndex = 0
        bunch.ChNameIndex = EName.Control

        bunch.serialize(bytes([NetControlMessageType.Hello]))
        bunch.serialize(bytes([1]))  # IsLittleEndian
        bunch.serialize_bits(conn.local_network_version.to_bytes(4, "little"), 32)
        bunch.serialize_fstring(EncryptionToken)
        bunch.serialize_bits(RuntimeFeatures.to_bytes(2, "little"), 16)

        return conn.get_raw_bunch(bunch, send_buffer)

    @staticmethod
    def Received(conn, bunch: FInBunch) -> None:
        bunch.serialize_bits(8)  # IsLittleEndian
        bunch.serialize_bits(32)  # NetworkVersion
        bunch.read_fstring()  # EncryptionToken
        bunch.serialize_bits(16)  # RuntimeFeatures
