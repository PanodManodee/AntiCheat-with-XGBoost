# commands/movement.py
"""Character Movement Component — outgoing RPC payload builders."""
from __future__ import annotations

from net.net_serialization import (
    compress_axis_to_byte,
    compress_axis_to_short,
    write_quantized_vector_scaled,
    write_rotator_compressed_short,
)
from serialization.bit_writer import FBitWriter


def _write_optional_uint8(writer, value: int, default: int) -> None:
    """1-bit flag + byte-if-different (FCharacterNetworkMoveData pattern)"""
    not_default = (int(value) & 0xFF) != (int(default) & 0xFF)
    writer.write_bit(not_default)
    if not_default:
        writer.serialize(bytes([int(value) & 0xFF]))


def build_server_move_packed_bits(
    ts: float,
    accel: dict[str, float],
    loc: dict[str, float],
    *,
    pitch: float = 0.0,
    yaw: float = 0.0,
    roll: float = 0.0,
    compressed_move_flags: int = 0,
    movement_mode: int = 1,
) -> tuple[bytes, int]:
    """Build the inner FCharacterNetworkMoveDataContainer bit payload"""
    w = FBitWriter(allow_resize=True)

    w.write_float(ts)
    write_quantized_vector_scaled(w, accel["x"], accel["y"], accel["z"], scale=10)
    write_quantized_vector_scaled(w, loc["x"], loc["y"], loc["z"], scale=100)
    write_rotator_compressed_short(w, pitch, yaw, roll)
    _write_optional_uint8(w, compressed_move_flags, 0)
    w.write_bit(False)   # MovementBase (nullptr)
    w.write_bit(False)   # MovementBaseBoneName (NAME_None)
    _write_optional_uint8(w, movement_mode, 1)

    w.write_bit(False)   # bHasPendingMove
    w.write_bit(False)   # bHasOldMove
    w.write_bit(False)   # bDisableCombinedScopedMove

    return w.get_buffer(), w.num_bits


def build_move_rpc_payload(
    rpc_variant: str,
    ts: float,
    accel: dict[str, float],
    loc: dict[str, float],
    *,
    pitch: float = 0.0,
    yaw: float = 0.0,
    roll: float = 0.0,
    compressed_move_flags: int = 0,
    movement_mode: int = 1,
) -> tuple[bytes, int]:
    """Build the full RPC parameter payload for the given move variant"""
    w = FBitWriter(allow_resize=True)

    if rpc_variant == "nobase":
        w.write_bit(True)
        w.write_float(ts)
        w.write_bit(True)
        write_quantized_vector_scaled(w, accel["x"], accel["y"], accel["z"], scale=10)
        w.write_bit(True)
        write_quantized_vector_scaled(w, loc["x"], loc["y"], loc["z"], scale=100)
        w.write_bit(True)
        w.serialize(bytes([compressed_move_flags]))
        w.write_bit(True)
        w.serialize(bytes([compress_axis_to_byte(roll)]))
        w.write_bit(True)
        w.write_uint32((compress_axis_to_short(yaw) << 16) | compress_axis_to_short(pitch))
        w.write_bit(True)
        w.serialize(bytes([movement_mode]))

    elif rpc_variant == "old":
        w.write_bit(True)
        w.write_float(ts)
        w.write_bit(True)
        write_quantized_vector_scaled(w, accel["x"], accel["y"], accel["z"], scale=10)
        w.write_bit(True)
        w.serialize(bytes([compressed_move_flags]))

    else:
        move_bits, move_num_bits = build_server_move_packed_bits(
            ts=ts, accel=accel, loc=loc,
            pitch=pitch, yaw=yaw, roll=roll,
            compressed_move_flags=compressed_move_flags,
            movement_mode=movement_mode,
        )
        w.write_bit(True)
        w.write_uint32_packed(move_num_bits)
        w.serialize_bits(move_bits, move_num_bits)

    return w.get_buffer(), w.num_bits
