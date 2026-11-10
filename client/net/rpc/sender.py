# net/rpc/sender.py
"""Outgoing RPC packet construction for actor channels."""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.names.ename import EName
from net.net_serialization import write_network_guid
from net.packets.out_bunch import FOutBunch
from serialization.bit_writer import FBitWriter

if TYPE_CHECKING:
    from net.connection import NetConnection


def build_actor_rpc_packet(
    conn: NetConnection,
    ch_index: int,
    field_index: int,
    field_max: int,
    rpc_payload: bytes,
    rpc_payload_bits: int,
    *,
    reliable: bool = True,
    clock_time_ms: int = 80,
) -> bytes:
    """Build a complete packet containing a single actor-channel RPC call.

    Constructs the content block (has_rep_layout=0, is_actor=1) with the given
    field index and RPC payload, wraps it in a bunch, and finalises via the
    connection's send-buffer pipeline.
    """
    # Field header + payload
    field_stream = FBitWriter(allow_resize=True)
    field_stream.serialize_int(field_index, max(field_max + 1, 2))
    field_stream.write_uint32_packed(rpc_payload_bits)
    if rpc_payload_bits > 0:
        field_stream.serialize_bits(rpc_payload, rpc_payload_bits)

    # Content block header
    block_stream = FBitWriter(allow_resize=True)
    block_stream.write_bit(False)   # has_rep_layout
    block_stream.write_bit(True)    # is_actor
    block_stream.write_uint32_packed(field_stream.num_bits)
    block_stream.serialize_bits(field_stream.get_buffer(), field_stream.num_bits)

    # Bunch + packet
    send_buffer = conn.init_send_buffer(clock_time_ms=clock_time_ms)
    bunch = FOutBunch(conn.max_bunch_payload_bits)
    bunch.ChIndex = ch_index
    bunch.ChNameIndex = int(EName.Actor)
    bunch.bReliable = reliable
    bunch.serialize_bits(block_stream.get_buffer(), block_stream.num_bits)
    return conn.get_raw_bunch(bunch, send_buffer)


def build_subobject_rpc_packet(
    conn: NetConnection,
    ch_index: int,
    subobject_guid: int,
    field_index: int,
    field_max: int,
    rpc_payload: bytes,
    rpc_payload_bits: int,
    *,
    reliable: bool = True,
    clock_time_ms: int = 80,
) -> bytes:
    """Build a packet containing an RPC call on a subobject (e.g. AbilitySystemComponent).

    Content block: has_rep_layout=0, is_actor=0, NetGUID of subobject.
    """
    # Field header + payload
    field_stream = FBitWriter(allow_resize=True)
    field_stream.serialize_int(field_index, max(field_max + 1, 2))
    field_stream.write_uint32_packed(rpc_payload_bits)
    if rpc_payload_bits > 0:
        field_stream.serialize_bits(rpc_payload, rpc_payload_bits)

    # Content block header — subobject variant
    block_stream = FBitWriter(allow_resize=True)
    block_stream.write_bit(False)   # has_rep_layout
    block_stream.write_bit(False)   # is_actor = False (subobject)
    write_network_guid(block_stream, subobject_guid)
    block_stream.write_uint32_packed(field_stream.num_bits)
    block_stream.serialize_bits(field_stream.get_buffer(), field_stream.num_bits)

    # Bunch + packet
    send_buffer = conn.init_send_buffer(clock_time_ms=clock_time_ms)
    bunch = FOutBunch(conn.max_bunch_payload_bits)
    bunch.ChIndex = ch_index
    bunch.ChNameIndex = int(EName.Actor)
    bunch.bReliable = reliable
    bunch.serialize_bits(block_stream.get_buffer(), block_stream.num_bits)
    return conn.get_raw_bunch(bunch, send_buffer)
