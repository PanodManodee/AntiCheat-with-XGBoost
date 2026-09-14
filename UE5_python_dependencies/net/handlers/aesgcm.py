# net/handlers/aesgcm.py
"""AES-GCM packet encryption handler"""
from __future__ import annotations

from serialization.bit_writer import FBitWriter
from serialization.bit_reader import FBitReader


class AESGCMHandlerComponent:
    """Enable and implement if the server config turns on AES-GCM encryption"""
    __slots__ = ()

    def Outgoing(self, packet: FBitWriter) -> FBitWriter:
        raise NotImplementedError("AESGCM encryption is not enabled for Lyra")

    def Incoming(self, packet: FBitReader) -> FBitReader:
        raise NotImplementedError("AESGCM encryption is not enabled for Lyra")
