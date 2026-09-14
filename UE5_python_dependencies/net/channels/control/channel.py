# net/channels/control/channel.py
"""Control channel for NMT messages."""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from net.channels.base_channel import Channel
from net.packets.in_bunch import FInBunch
from net.packets.control import NetControlMessageType
from net.state.session_state import get_session_state

if TYPE_CHECKING:
    from net.connection import NetConnection
    from net.state.session_state import SessionState

ControlMessageHandler = Callable[['ControlChannel', 'NetConnection', FInBunch, 'SessionState'], None]


def _build_default_handlers() -> dict[int, ControlMessageHandler]:
    from .core_handlers import get_handlers as get_core
    handlers: dict[int, ControlMessageHandler] = {}
    handlers.update(get_core())
    return handlers


class ControlChannel(Channel):
    __slots__ = ('_handlers',)

    def __init__(self, connection, ch_index, ch_name):
        super().__init__(connection, ch_index, ch_name)
        self._handlers: dict[int, ControlMessageHandler] = _build_default_handlers()

    def register_handler(self, msg_type: NetControlMessageType | int, handler: ControlMessageHandler) -> None:
        self._handlers[int(msg_type)] = handler

    def unregister_handler(self, msg_type: NetControlMessageType | int) -> None:
        self._handlers.pop(int(msg_type), None)

    def received_bunch(self, connection, bunch: FInBunch) -> None:
        session = get_session_state(connection)
        while not bunch.at_end():
            if bunch.is_error() or connection.b_closed:
                break
            msg_type = bunch.serialize(1)[0]
            if bunch.is_error():
                break
            pos_after_type = bunch.get_pos_bits()
            handler = self._handlers.get(msg_type)
            if handler is not None:
                handler(self, connection, bunch, session)
            if bunch.is_error():
                break
            if bunch.get_pos_bits() == pos_after_type and not bunch.at_end():
                self._consume_remaining(bunch)
                break

    @staticmethod
    def _consume_remaining(bunch: FInBunch) -> None:
        bits_left = bunch.get_bits_left()
        if bits_left > 0:
            bunch.serialize_bits(bits_left)

    consume_remaining = _consume_remaining
