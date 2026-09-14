# net/replication/custom_delta/base.py
"""Custom delta property handler base class and registry."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader


class CustomDeltaBase:
    """Base class for custom delta property handlers.

    Subclasses set ``names`` to the field names they handle
    and implement ``receive`` to deserialize the payload.
    """
    names: tuple[str, ...] = ()

    @classmethod
    def receive(cls, reader: 'FBitReader', context: Any = None) -> Optional[dict[str, Any]]:
        raise NotImplementedError


class CustomDeltaRegistry:
    _handlers: dict[str, type[CustomDeltaBase]] = {}

    @classmethod
    def register(cls, handler: type[CustomDeltaBase]) -> None:
        for name in handler.names:
            cls._handlers[name] = handler

    @classmethod
    def register_all(cls, handlers: list[type[CustomDeltaBase]]) -> None:
        for handler in handlers:
            cls.register(handler)

    @classmethod
    def receive(
        cls,
        field_name: str,
        reader: 'FBitReader',
        context: Any = None,
    ) -> Optional[dict[str, Any]]:
        handler = cls._handlers.get(field_name)
        if handler:
            return handler.receive(reader, context)
        return None
