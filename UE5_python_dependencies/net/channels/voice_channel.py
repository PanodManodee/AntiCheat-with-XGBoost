# net/channels/voice_channel.py
"""Voice channel (payload is currently ignored)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from net.channels.base_channel import Channel
from net.packets.in_bunch import FInBunch

if TYPE_CHECKING:
    from net.connection import NetConnection


class VoiceChannel(Channel):
    def received_bunch(self, connection: "NetConnection", bunch: FInBunch) -> None:
        bits_left = bunch.get_bits_left()
        if bits_left > 0:
            bunch.serialize_bits(bits_left)
