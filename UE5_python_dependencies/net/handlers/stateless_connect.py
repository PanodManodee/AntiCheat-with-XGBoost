# net/handlers/stateless_connect.py
"""Stateless connection handshake handler."""
from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
import os
import random

from serialization.bit_writer import FBitWriter
from serialization.bit_reader import FBitReader
from constants import HANDSHAKE_COOKIE_SIZE


class HandshakePacketType(IntEnum):
    Initial = 0
    Challenge = 1
    Response = 2
    Ack = 3
    RestartHandshake = 4
    RestartResponse = 5
    VersionUpgrade = 6


class HandshakeVersion(IntEnum):
    Original = 0
    Randomized = 1
    NetCLVersion = 2
    SessionClientId = 3
    NetCLUpgradeMessage = 4
    Latest = 4


@dataclass(slots=True)
class ParsedHandshake:
    CachedGlobalNetTravelCount: int
    CachedClientID: int
    bRestartedHandshake: bool
    MinSupportedHandshakeVersion: int
    HandshakeVersion: int
    PacketType: int
    SentHandshakePacketCount: int
    LocalNetworkVersion: int
    RuntimeFeatures: int
    SecretId: int
    Timestamp: float
    Cookie: bytes


class StatelessConnectHandlerComponent:
    __slots__ = (
        '_magic', 'LocalNetworkVersion', 'CachedClientID',
        'CachedGlobalNetTravelCount', 'SentHandshakePacketCount',
        'MinSupportedHandshakeVersion', 'RuntimeFeatures',
    )

    def __init__(self, magic_header: bytes = b"", CachedClientID: int = 0, LocalNetworkVersion: int = 0, RuntimeFeatures: int = 0):
        self._magic = magic_header
        self.LocalNetworkVersion = LocalNetworkVersion
        self.CachedClientID = CachedClientID
        self.CachedGlobalNetTravelCount = 0
        self.SentHandshakePacketCount = 0
        self.MinSupportedHandshakeVersion = int(HandshakeVersion.SessionClientId)
        self.RuntimeFeatures = RuntimeFeatures

    def get_initial_packet(self, version: int = HandshakeVersion.Latest) -> bytes:
        max_bits = (441 if version >= HandshakeVersion.SessionClientId else 436) + len(self._magic) * 8
        w = FBitWriter(max_bits=max_bits, allow_resize=True)

        self._begin_handshake(w, HandshakePacketType.Initial, version, self.CachedClientID, False)

        w.write_bit(0)  # SecretId
        w.write_double(0.0)  # Timestamp
        w.serialize(b"\x00" * HANDSHAKE_COOKIE_SIZE)  # Cookie

        self._cap_handshake(w, version)
        return w.get_buffer()

    def _begin_handshake(self, w: FBitWriter, pkt_type: int, version: int, client_id: int, restarted: bool) -> None:
        if self._magic:
            w.serialize(self._magic)

        if version >= HandshakeVersion.SessionClientId:
            w.serialize_bits(self.CachedGlobalNetTravelCount.to_bytes(1, "little"), 2)
            w.serialize_bits(client_id.to_bytes(1, "little"), 3)

        w.write_bit(True)  # bHandshakePacket
        w.write_bit(restarted)

        if version >= HandshakeVersion.Randomized:
            w.serialize(bytes([self.MinSupportedHandshakeVersion, version, pkt_type, self.SentHandshakePacketCount]))

        if version >= HandshakeVersion.NetCLVersion:
            w.serialize_bits(self.LocalNetworkVersion.to_bytes(4, "little"), 32)
            w.serialize_bits(self.RuntimeFeatures.to_bytes(2, "little"), 16)

    def _cap_handshake(self, w: FBitWriter, version: int) -> None:
        if version != HandshakeVersion.Original:
            w.serialize(os.urandom(random.randint(8, 16)))
        w.write_bit(1)
        self.SentHandshakePacketCount += 1

    def parse_handshake_packet(self, packet: bytes) -> ParsedHandshake:
        r = FBitReader(packet)

        data = ParsedHandshake(
            CachedGlobalNetTravelCount=r.read_int(4),
            CachedClientID=r.read_int(8),
            bRestartedHandshake=False,
            MinSupportedHandshakeVersion=0,
            HandshakeVersion=0,
            PacketType=0,
            SentHandshakePacketCount=0,
            LocalNetworkVersion=0,
            RuntimeFeatures=0,
            SecretId=0,
            Timestamp=0.0,
            Cookie=b""
        )

        if not r.read_bit():
            raise ValueError("Not a handshake packet")

        data.bRestartedHandshake = bool(r.read_bit())
        if data.bRestartedHandshake:
            raise ValueError("Restarted handshake not supported")

        data.MinSupportedHandshakeVersion = r.serialize_bits(8)[0]
        data.HandshakeVersion = r.serialize_bits(8)[0]
        data.PacketType = r.serialize_bits(8)[0]
        data.SentHandshakePacketCount = r.serialize_bits(8)[0]

        if data.HandshakeVersion >= HandshakeVersion.NetCLVersion:
            data.LocalNetworkVersion = int.from_bytes(r.serialize_bits(32), "little")
            data.RuntimeFeatures = int.from_bytes(r.serialize_bits(16), "little")

        data.SecretId = 1 if r.read_bit() else 0
        data.Timestamp = r.read_double()
        data.Cookie = r.serialize(HANDSHAKE_COOKIE_SIZE)

        return data

    def get_challenge_response_packet(self, challenge: ParsedHandshake) -> bytes:
        if len(challenge.Cookie) != HANDSHAKE_COOKIE_SIZE:
            raise ValueError("Cookie must be 20 bytes")

        base = 307 + (5 if challenge.HandshakeVersion >= HandshakeVersion.NetCLVersion else 0)
        max_bits = base + len(self._magic) * 8 + 129
        w = FBitWriter(max_bits=max_bits, allow_resize=True)

        self._begin_handshake(
            w, HandshakePacketType.Response, challenge.HandshakeVersion,
            challenge.CachedClientID, False
        )

        w.write_bit(challenge.SecretId)
        w.write_double(challenge.Timestamp)
        w.serialize(challenge.Cookie)

        self._cap_handshake(w, challenge.HandshakeVersion)
        return w.get_buffer()

    def Outgoing(self, packet: FBitWriter) -> FBitWriter:
        out = FBitWriter(packet.num_bits + 8, allow_resize=True)

        if self._magic:
            out.serialize(self._magic)

        out.serialize_bits(self.CachedGlobalNetTravelCount.to_bytes(1, "little"), 2)
        out.serialize_bits(self.CachedClientID.to_bytes(1, "little"), 3)
        out.write_bit(False)  # Not handshake
        out.serialize_bits(packet.get_buffer(), packet.num_bits)

        return out

    def Incoming(self, packet: FBitReader) -> FBitReader:
        if self._magic:
            self._magic = packet.serialize(len(self._magic))

        self.CachedGlobalNetTravelCount = packet.read_int(4)
        self.CachedClientID = packet.read_int(8)

        if packet.read_bit():
            raise NotImplementedError("Handshake packet in Incoming not supported")

        remaining = packet.get_bits_left()
        return FBitReader(packet.serialize_bits(remaining), num_bits=remaining)
