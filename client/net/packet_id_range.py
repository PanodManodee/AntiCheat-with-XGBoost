# net/packet_id_range.py
"""FPacketIdRange for tracking packet ranges."""
from __future__ import annotations


class FPacketIdRange:
    INDEX_NONE = -1
    __slots__ = ('first', 'last')

    def __init__(self, first=INDEX_NONE, last=None):
        if last is None:
            self.first = first
            self.last = first
        else:
            self.first = first
            self.last = last

    def in_range(self, packet_id):
        return self.first <= packet_id <= self.last

    def __contains__(self, packet_id):
        return self.in_range(packet_id)

    def __iter__(self):
        yield self.first
        yield self.last

    def __repr__(self):
        return f"FPacketIdRange({self.first}, {self.last})"

    def __eq__(self, other):
        return (
            isinstance(other, FPacketIdRange)
            and self.first == other.first
            and self.last == other.last
        )
