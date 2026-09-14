# net/replication/types.py
"""Replication-specific types (RepLayout definitions)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader


class PropertyType(IntEnum):
    """Maps to ERepLayoutCmdType."""
    BOOL = 0
    BYTE = 1
    INT = 2
    FLOAT = 3
    DOUBLE = 4
    INT8 = 5
    INT16 = 6
    INT64 = 7
    UINT16 = 8
    UINT32 = 9
    UINT64 = 10

    VECTOR = 20
    ROTATOR = 21
    VECTOR_DOUBLE = 22
    ROTATOR_DOUBLE = 23
    PLANE = 24
    QUAT = 25
    TRANSFORM = 26

    STRING = 30
    NAME = 31
    TEXT = 32

    OBJECT = 40
    SOFT_OBJECT = 41
    WEAK_OBJECT = 42
    INTERFACE = 43
    CLASS = 44

    ARRAY = 50
    MAP = 51
    SET = 52

    STRUCT = 60
    NET_SERIALIZE = 61
    PROPERTY = 62

    DYNAMIC_ARRAY = 70
    RETURN = 71


@dataclass(slots=True)
class PropertyDef:
    """RepLayout property definition."""
    name: str
    prop_type: PropertyType
    handle: int
    offset: int = 0
    serializer: Optional[Callable[['FBitReader', Optional[Any]], Any]] = None
    array_dim: int = 1
    condition: int = 0
    inner_defs: list['PropertyDef'] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"PropertyDef({self.name!r}, {self.prop_type.name}, handle={self.handle})"


@dataclass(slots=True)
class RepLayoutTemplate:
    """Matching pattern + callbacks for a class family."""
    match: Callable[[str], bool]
    on_update: Optional[Callable[[dict, Any], None]] = None
