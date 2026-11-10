# net/identity/unique_net_id_repl.py
"""FUniqueNetIdRepl for replicated network identification."""
from __future__ import annotations

import binascii

from core.names.fname import FName
from net.identity.unique_net_id import FUniqueNetId
from serialization.bit_reader import FBitReader
from serialization.bit_writer import FBitWriter


class EUniqueIdEncodingFlags:
    NotEncoded = 0
    IsEncoded = 1
    IsEmpty = 2
    IsPadded = 4
    FlagsMask = 7
    TypeMask = 248


# UE5 OnlineSubsystem type hash table (OnlineSubsystemUtilsModule.cpp CreateNameHashes)
# Hash 0 = invalid/unknown, 30 = V2 AccountId, 31 = Other (type FString follows)
_HASH_TO_SUBSYSTEM: dict[int, str] = {
    1: "NULL",
    2: "MCP",
    3: "STEAM",
    4: "PS4",
    5: "GOOGLE",
    6: "GOOGLEPLAY",
    7: "FACEBOOK",
    8: "IOS",
    9: "APPLE",
    10: "TENCENT",
    11: "NINTENDO",
    12: "AMAZON",
    13: "GAMECIRCLE",
    14: "THUNDERHEAD",
    15: "ONESTORE",
    16: "PS4SERVER",
}

_SUBSYSTEM_TO_HASH: dict[str, int] = {v: k for k, v in _HASH_TO_SUBSYSTEM.items()}


class FUniqueNetIdRepl:
    __slots__ = ('UniqueNetId', 'ReplicationBytes')

    TypeHashOther = 31
    TypeHashV2 = 30

    def __init__(self, unique_net_id: FUniqueNetId | None = None):
        self.UniqueNetId: FUniqueNetId | None = unique_net_id
        self.ReplicationBytes: FBitWriter | None = None

    @classmethod
    def from_unique_id(cls, unique_net_id: FUniqueNetId) -> FUniqueNetIdRepl:
        return cls(unique_net_id)

    @classmethod
    def invalid(cls) -> FUniqueNetIdRepl:
        return cls()

    def is_valid(self) -> bool:
        return self.UniqueNetId is not None and self.UniqueNetId.is_valid()

    def get_unique_net_id(self) -> FUniqueNetId | None:
        return self.UniqueNetId

    def set_unique_net_id(self, unique_net_id: FUniqueNetId | None) -> None:
        self.UniqueNetId = unique_net_id
        self.ReplicationBytes = None

    def get_type(self) -> FName:
        if self.UniqueNetId is not None:
            return self.UniqueNetId.get_type()
        return FName()

    def to_string(self) -> str:
        if self.UniqueNetId is not None:
            return self.UniqueNetId.to_string()
        return ''

    def to_debug_string(self) -> str:
        if self.is_valid():
            return f"{self.UniqueNetId.type}: {self.UniqueNetId.contents}"
        return "INVALID"

    def __str__(self) -> str:
        return self.to_debug_string()

    def __repr__(self) -> str:
        return f"FUniqueNetIdRepl({self.UniqueNetId!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FUniqueNetIdRepl):
            return NotImplemented
        if self.UniqueNetId is None and other.UniqueNetId is None:
            return True
        if self.UniqueNetId is None or other.UniqueNetId is None:
            return False
        return self.UniqueNetId == other.UniqueNetId

    def __hash__(self) -> int:
        if self.UniqueNetId is not None:
            return hash(self.UniqueNetId)
        return hash(None)

    @staticmethod
    def get_type_hash_from_encoding(flags: int) -> int:
        raw = (flags & EUniqueIdEncodingFlags.TypeMask) >> 3
        return raw if raw < 32 else 0

    def net_serialize(self, ar: FBitReader) -> bool:
        self.UniqueNetId = None
        flags = ar.serialize(1)[0]

        if flags & EUniqueIdEncodingFlags.IsEncoded:
            if flags & EUniqueIdEncodingFlags.IsEmpty:
                return True

            th = self.get_type_hash_from_encoding(flags)

            if th == self.TypeHashV2:
                self._net_serialize_load_v2(ar)
                return True

            return self._net_serialize_load_v1_encoded(ar, flags, th)

        return self._net_serialize_load_v1_unencoded(ar, flags)

    @staticmethod
    def _resolve_type_name(th: int, ar: FBitReader | None = None) -> str:
        if th == FUniqueNetIdRepl.TypeHashOther:
            return ar.read_fstring() if ar else ""
        return _HASH_TO_SUBSYSTEM.get(th, "")

    def _net_serialize_load_v1_encoded(self, ar: FBitReader, flags: int, th: int) -> bool:
        type_name = self._resolve_type_name(th, ar)

        size = ar.serialize(1)[0]
        if size == 0:
            return True

        raw = ar.serialize(size)
        contents = binascii.hexlify(raw).decode("ascii")

        if flags & EUniqueIdEncodingFlags.IsPadded:
            contents = contents[1:]

        self.UniqueNetId = FUniqueNetId(FName(type_name) if type_name else FName(), contents)
        return True

    def _net_serialize_load_v1_unencoded(self, ar: FBitReader, flags: int) -> bool:
        th = self.get_type_hash_from_encoding(flags)
        type_name = self._resolve_type_name(th, ar)

        contents = ar.read_fstring()
        self.UniqueNetId = FUniqueNetId(FName(type_name) if type_name else FName(), contents)
        return True

    def _net_serialize_load_v2(self, ar: FBitReader) -> None:
        online_services_type = ar.read_byte()
        num_bytes = ar.read_int32()
        if num_bytes > 0:
            data = ar.serialize(num_bytes)
            self.UniqueNetId = FUniqueNetId(FName(), binascii.hexlify(data).decode("ascii"))

    @staticmethod
    def serialize(ar: FBitReader, instance: FUniqueNetIdRepl) -> None:
        instance.net_serialize(ar)

    @classmethod
    def read(cls, ar: FBitReader) -> FUniqueNetIdRepl:
        inst = cls()
        cls.serialize(ar, inst)
        return inst

    def _make_replication_data(self) -> None:
        if self.is_valid():
            self._make_replication_data_v1()
        else:
            bw = FBitWriter(max_bits=8, allow_resize=True)
            flags_byte = EUniqueIdEncodingFlags.IsEncoded | EUniqueIdEncodingFlags.IsEmpty
            bw.serialize(bytes([flags_byte]))
            self.ReplicationBytes = bw

    def _make_replication_data_v1(self) -> None:
        contents: str = self.UniqueNetId.contents if self.UniqueNetId and self.UniqueNetId.contents else ""
        length = len(contents)

        if length == 0:
            bw = FBitWriter(max_bits=8, allow_resize=True)
            flags_byte = EUniqueIdEncodingFlags.IsEncoded | EUniqueIdEncodingFlags.IsEmpty
            bw.serialize(bytes([flags_byte]))
            self.ReplicationBytes = bw
            return

        uid_type = self.UniqueNetId.type
        type_name = str(uid_type) if uid_type and uid_type.index != 0 else ""
        if type_name:
            type_hash = _SUBSYSTEM_TO_HASH.get(type_name, self.TypeHashOther)
        else:
            type_hash = 0

        b_even_chars = (length % 2) == 0
        encoded_size = (length + 1) // 2

        b_is_numeric = contents.isdigit()

        if b_is_numeric:
            encoding_flags = EUniqueIdEncodingFlags.IsEncoded
            b_is_padded = not b_even_chars
        elif b_even_chars and encoded_size < 255:
            is_lowercase_hex = all(c in '0123456789abcdef' for c in contents)
            if is_lowercase_hex:
                encoding_flags = EUniqueIdEncodingFlags.IsEncoded
            else:
                encoding_flags = EUniqueIdEncodingFlags.NotEncoded
            b_is_padded = False
        else:
            encoding_flags = EUniqueIdEncodingFlags.NotEncoded
            b_is_padded = False

        if b_is_padded:
            encoding_flags |= EUniqueIdEncodingFlags.IsPadded

        flags_byte = ((type_hash & 0x1F) << 3) | (encoding_flags & EUniqueIdEncodingFlags.FlagsMask)

        bw = FBitWriter(allow_resize=True)
        bw.serialize(bytes([flags_byte]))

        if type_hash == self.TypeHashOther:
            bw.serialize_fstring(type_name)

        if encoding_flags & EUniqueIdEncodingFlags.IsEncoded:
            hex_str = ("0" + contents) if b_is_padded else contents
            raw = binascii.unhexlify(hex_str.encode("ascii"))
            bw.serialize(bytes([len(raw)]))
            bw.serialize(raw)
        else:
            bw.serialize_fstring(contents)

        self.ReplicationBytes = bw

    def write(self, writer: FBitWriter) -> None:
        if not self.ReplicationBytes or self.ReplicationBytes.num_bits == 0:
            self._make_replication_data()

        data = self.ReplicationBytes.get_buffer()
        writer.serialize(data)
