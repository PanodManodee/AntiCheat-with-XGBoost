# net/packets/control/login.py
from __future__ import annotations
from net.packets.out_bunch import FOutBunch
from net.packets.in_bunch import FInBunch
from net.packets.control import NetControlMessageType
from net.identity.unique_net_id_repl import FUniqueNetIdRepl
from net.identity.unique_net_id import FUniqueNetId
from app_config import ONLINE_SUBSYSTEM_TYPE
from core.names.ename import EName
from core.names.fname import FName


class Login:
    @staticmethod
    def Get(conn, ClientResponse: str = "0", URL: str = "", PlayerId: str = "", PlayerOnlinePlatformName: str = "NULL") -> bytes:
        send_buffer = conn.init_send_buffer(1000)

        bunch = FOutBunch(conn.max_bunch_payload_bits)
        bunch.bReliable = True
        bunch.ChNameIndex = EName.Control

        bunch.serialize(bytes([NetControlMessageType.Login]))
        bunch.serialize_fstring(ClientResponse)
        bunch.serialize_fstring(URL)

        repl = FUniqueNetIdRepl()
        repl.UniqueNetId = FUniqueNetId(FName(ONLINE_SUBSYSTEM_TYPE), PlayerId)
        repl.write(bunch)

        bunch.serialize_fstring(PlayerOnlinePlatformName)

        return conn.get_raw_bunch(bunch, send_buffer)

    @staticmethod
    def Received(conn, bunch: FInBunch) -> None:
        bunch.read_fstring()  # ClientResponse
        bunch.read_fstring()  # URL
        FUniqueNetIdRepl.read(bunch)  # PlayerId
        bunch.read_fstring()  # PlayerOnlinePlatformName
