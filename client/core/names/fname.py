# core/names/fname.py
"""UE5 FName implementation."""
from __future__ import annotations
from typing import Union, Optional
from core.names.ename import EName


class _FNamePool:
    """Global name pool (singleton via module-level instance)."""
    __slots__ = ('_by_index', '_by_name')

    def __init__(self):
        self._by_index: dict[int, str] = {0: "None"}
        self._by_name: dict[str, int] = {"None": 0}

    def find(self, name: Union[EName, int, str]) -> int:
        if isinstance(name, EName):
            return name.value
        if isinstance(name, int):
            return name
        if name in self._by_name:
            return self._by_name[name]
        idx = len(self._by_name)
        self._by_name[name] = idx
        self._by_index[idx] = name
        return idx

    def resolve(self, index: int) -> str:
        return self._by_index.get(index, f"Name_{index}")

    def to_ename(self, index: int) -> Optional[EName]:
        try:
            return EName(index)
        except ValueError:
            return None


_pool = _FNamePool()


class FName:
    """UE5 FName - indexed string with optional number suffix."""
    __slots__ = ('index', 'number')

    def __init__(self, name: Union[EName, int, str] = EName.None_, number: int = 0):
        self.index = _pool.find(name)
        self.number = number

    @property
    def plain_name(self) -> str:
        return _pool.resolve(self.index)

    def to_ename(self) -> Optional[EName]:
        return _pool.to_ename(self.index)

    def __str__(self) -> str:
        return f"{self.plain_name}_{self.number}" if self.number else self.plain_name

    def __repr__(self) -> str:
        return f"FName({self.plain_name!r}, {self.number})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FName):
            return NotImplemented
        return self.index == other.index and self.number == other.number

    def __hash__(self) -> int:
        return hash((self.index, self.number))
