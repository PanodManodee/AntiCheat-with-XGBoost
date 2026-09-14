# net/identity/unique_net_id.py
"""FUniqueNetId for network identification."""
from __future__ import annotations

import binascii
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.names.fname import FName


class FUniqueNetId:
    __slots__ = ('type', 'contents')

    def __init__(self, type_name: FName, contents: str = ''):
        self.type: FName = type_name
        self.contents: str = contents

    def is_valid(self) -> bool:
        return bool(self.contents)

    def get_type(self) -> FName:
        return self.type

    def get_size(self) -> int:
        """Get the size in bytes of the hex-encoded ID data."""
        return len(self.contents) // 2 if self.contents else 0

    def get_bytes(self) -> bytes:
        """Get raw byte representation of the ID data."""
        if not self.contents:
            return b''
        try:
            return binascii.unhexlify(self.contents)
        except (ValueError, binascii.Error):
            return self.contents.encode('utf-8')

    def to_string(self) -> str:
        return self.contents or ''

    def to_debug_string(self) -> str:
        if self.is_valid():
            return f"{self.type}:{self.contents}"
        return "INVALID"

    def __str__(self) -> str:
        return self.to_debug_string()

    def __repr__(self) -> str:
        return f"FUniqueNetId(type={self.type!s}, contents={self.contents!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FUniqueNetId):
            return NotImplemented
        return self.type == other.type and self.contents == other.contents

    def __hash__(self) -> int:
        return hash((str(self.type), self.contents))
