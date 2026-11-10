# net/rpc/base.py
"""RPC parser base class and registry."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader


class RPCBase:
    names: tuple[str, ...] = ()

    @classmethod
    def parse(cls, reader: 'FBitReader') -> Optional[dict[str, Any]]:
        raise NotImplementedError


class RPCRegistry:
    _handlers: dict[str, type[RPCBase]] = {}

    @classmethod
    def register(cls, handler: type[RPCBase]) -> None:
        for name in handler.names:
            cls._handlers[name] = handler

    @classmethod
    def register_all(cls, parsers: list[type[RPCBase]]) -> None:
        for parser in parsers:
            cls.register(parser)

    @classmethod
    def parse(cls, rpc_name: str, reader: 'FBitReader') -> Optional[dict[str, Any]]:
        handler = cls._handlers.get(rpc_name)
        if handler:
            return handler.parse(reader)
        return None
