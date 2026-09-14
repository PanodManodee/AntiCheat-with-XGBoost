# net/net_serialization.py
"""UE5 network type serialization"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from net.error_reporter import report_exception, PARSE_EXCEPTIONS
from net.types import FVector, FRotator
from constants import (
    ENGINE_NET_VER_CURRENT,
    ENGINE_NET_VER_OPTIONALLY_QUANTIZE_SPAWN_INFO,
    ENGINE_NET_VER_SERIALIZE_DOUBLE_VECTORS_AS_DOUBLES,
    ENGINE_NET_VER_PACKED_VECTOR_LWC_SUPPORT,
    ENGINE_NET_VER_REP_MOVE_SERVER_FRAME_AND_HANDLE,
    ENGINE_NET_VER_21_AND_VIEW_PITCH_ONLY_DONOTUSE,
    ENGINE_NET_VER_PREDICTION_KEY_BASE_NOT_REPLICATED,
    ENGINE_NET_VER_REP_MOVE_OPTIONAL_ACCELERATION,
    NET_GUID_PACKED64,
)

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader
    from serialization.bit_writer import FBitWriter


def _bytes_to_int_lsb(data: bytes, n_bits: int) -> int:
    val = 0
    for i, byte in enumerate(data):
        val |= byte << (8 * i)
    return val & ((1 << n_bits) - 1)


def _to_signed(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val ^ sign_bit) - sign_bit


def _ver_check(engine_ver: int, threshold: int) -> bool:
    """EngineNetVer >= threshold AND != Ver21AndViewPitchOnly_DONOTUSE."""
    return (engine_ver >= threshold
            and engine_ver != ENGINE_NET_VER_21_AND_VIEW_PITCH_ONLY_DONOTUSE)


# ---------------------------------------------------------------------------
# FVector
# ---------------------------------------------------------------------------

def read_vector_double(reader: 'FBitReader', engine_ver: int = ENGINE_NET_VER_CURRENT) -> Optional[FVector]:
    """FVector3d::NetSerialize.

    v22+ (SerializeDoubleVectorsAsDoubles): 3 x double (192 bits).
    Older: 3 x float (96 bits), cast to double.
    """
    if _ver_check(engine_ver, ENGINE_NET_VER_SERIALIZE_DOUBLE_VECTORS_AS_DOUBLES):
        if reader.get_bits_left() < 192:
            return None
        return FVector(reader.read_double(), reader.read_double(), reader.read_double())
    else:
        if reader.get_bits_left() < 96:
            return None
        return FVector(reader.read_float(), reader.read_float(), reader.read_float())


# ---------------------------------------------------------------------------
# Quantized vector
# ---------------------------------------------------------------------------

# Legacy packed vector MaxBitsPerComponent per scale factor
_LEGACY_MAX_BITS = {1: 20, 10: 24, 100: 30}

def _read_legacy_packed_vector(reader: 'FBitReader', scale: int, max_bits_per_component: int) -> Optional[FVector]:
    """LegacyReadPackedVector (pre-v23 format).

    Header: SerializeInt(MaxBitsPerComponent) → bits-per-component count.
    Per component: SerializeInt(1 << (bits+2)) biased unsigned integer.
    Decode: (raw - bias) / scale,  where bias = 1 << (bits+1).
    """
    start_pos = reader.get_pos_bits()
    try:
        bits = reader.read_int(max_bits_per_component)
    except PARSE_EXCEPTIONS:
        report_exception("_read_legacy_packed_vector header failed")
        reader.set_pos_bits(start_pos)
        return None

    bias = 1 << (bits + 1)
    max_val = 1 << (bits + 2)

    try:
        dx = reader.read_int(max_val)
        dy = reader.read_int(max_val)
        dz = reader.read_int(max_val)
    except PARSE_EXCEPTIONS:
        report_exception("_read_legacy_packed_vector components failed")
        reader.set_pos_bits(start_pos)
        return None

    fact = float(scale)
    return FVector(
        (dx - bias) / fact,
        (dy - bias) / fact,
        (dz - bias) / fact,
    )


def read_quantized_vector(reader: 'FBitReader', scale: int = 10, engine_ver: int = ENGINE_NET_VER_CURRENT) -> Optional[FVector]:
    """FVector_NetQuantize*::NetSerialize — version-aware.

    v23+ (PackedVectorLWCSupport): ReadQuantizedVector.
      Header: SerializeInt(128) → 7 bits
        bits 0-5: N (bits per component)
        bit 6:    scaled flag
      Payload: N-bit signed integer per component, or float/double fallback.

    Older: LegacyReadPackedVector.
      Header: SerializeInt(MaxBitsPerComponent)
      Per component: SerializeInt(1 << (bits+2)) with bias.
    """
    if not _ver_check(engine_ver, ENGINE_NET_VER_PACKED_VECTOR_LWC_SUPPORT):
        max_bits = _LEGACY_MAX_BITS.get(scale, 24)
        return _read_legacy_packed_vector(reader, scale, max_bits)

    # --- v23+ ReadQuantizedVector ---
    if reader.get_bits_left() < 1:
        return None

    start_pos = reader.get_pos_bits()

    try:
        header = reader.read_int(128)
    except PARSE_EXCEPTIONS:
        report_exception("read_quantized_vector failed")
        reader.set_pos_bits(start_pos)
        return None

    n_bits = header & 0x3F
    is_scaled = bool(header & 0x40)

    if n_bits == 0:
        if is_scaled:
            if reader.get_bits_left() < 192:
                reader.set_pos_bits(start_pos)
                return None
            return FVector(reader.read_double(), reader.read_double(), reader.read_double())
        else:
            if reader.get_bits_left() < 96:
                reader.set_pos_bits(start_pos)
                return None
            return FVector(reader.read_float(), reader.read_float(), reader.read_float())

    if reader.get_bits_left() < n_bits * 3:
        reader.set_pos_bits(start_pos)
        return None

    x_raw = _bytes_to_int_lsb(reader.serialize_bits(n_bits), n_bits)
    y_raw = _bytes_to_int_lsb(reader.serialize_bits(n_bits), n_bits)
    z_raw = _bytes_to_int_lsb(reader.serialize_bits(n_bits), n_bits)

    x = _to_signed(x_raw, n_bits)
    y = _to_signed(y_raw, n_bits)
    z = _to_signed(z_raw, n_bits)

    if is_scaled:
        return FVector(x / scale, y / scale, z / scale)
    return FVector(float(x), float(y), float(z))


# ---------------------------------------------------------------------------
# Rotators
# ---------------------------------------------------------------------------

def read_rotation_short(reader: 'FBitReader') -> Optional[FRotator]:
    """Fixed 48-bit rotator (3 x uint16)."""
    if reader.get_bits_left() < 48:
        return None
    return FRotator(
        reader.read_uint16() * 360.0 / 65536.0,
        reader.read_uint16() * 360.0 / 65536.0,
        reader.read_uint16() * 360.0 / 65536.0,
    )


def read_rotation_compressed_short(reader: 'FBitReader') -> Optional[FRotator]:
    """TRotator<double>::NetSerialize → SerializeCompressedShort.

    Per component: 1-bit nonzero flag + uint16 if set.
    """
    components = []
    for _ in range(3):
        if reader.get_bits_left() < 1:
            return None
        if reader.read_bit():
            if reader.get_bits_left() < 16:
                return None
            components.append(reader.read_uint16() * (360.0 / 65536.0))
        else:
            components.append(0.0)
    return FRotator(*components)


def read_rotator_smart_pitch(reader: 'FBitReader') -> Optional[FRotator]:
    """FRotator_NetQuantizeSmartPitch::NetSerialize.

    Yaw:   8-bit signed byte (* 1.4173229 deg)
    Pitch: 1-bit flag; if set, 8-bit signed byte (* 1.4173229 deg); else 0
    Roll:  always 0
    """
    if reader.get_bits_left() < 9:
        return None
    yaw_byte = reader.read_int8()
    yaw = yaw_byte * 1.4173229
    pitch = 0.0
    if reader.read_bit():
        if reader.get_bits_left() < 8:
            return None
        pitch_byte = reader.read_int8()
        pitch = pitch_byte * 1.4173229
    return FRotator(pitch, yaw, 0.0)


# ---------------------------------------------------------------------------
# Object / FName
# ---------------------------------------------------------------------------

def read_network_guid(reader: 'FBitReader') -> int:
    """Read FNetworkGUID value from the bitstream.

    Standard UE5: raw uint32 — FArchive::operator<<(FNetworkGUID&)
    Controlled by NET_GUID_PACKED64 constant.
    """
    if NET_GUID_PACKED64:
        return reader.read_uint64_packed()
    return reader.read_uint32()


def write_network_guid(writer: 'FBitWriter', value: int) -> None:
    """Write FNetworkGUID value to the bitstream."""
    if NET_GUID_PACKED64:
        writer.write_uint64_packed(int(value))
    else:
        writer.write_uint32(int(value) & 0xFFFFFFFF)


def read_fname(reader: 'FBitReader') -> str:
    """FName — UE5 StaticSerializeName.

    Wire format: 1-bit bIsHardcoded flag.
      If set:  packed uint32 index into hardcoded name table.
      Else:    FString + int32 number suffix.
    """
    if reader.read_bit():
        return f"EName_{reader.read_uint32_packed()}"
    name = reader.read_fstring()
    number = reader.read_int32()
    return f"{name}_{number}" if number else name


# ---------------------------------------------------------------------------
# Fixed compressed float / normal vector
# ---------------------------------------------------------------------------

def read_fixed_compressed_float(reader: 'FBitReader', max_value: int, num_bits: int) -> float:
    """ReadFixedCompressedFloat<MaxValue, NumBits>"""
    ser_int_max = 1 << num_bits
    max_bit_value = (1 << (num_bits - 1)) - 1
    bias = 1 << (num_bits - 1)

    delta = reader.read_int(ser_int_max)
    unscaled = float(delta - bias)

    if max_value > max_bit_value:
        inv_scale = max_value / float(max_bit_value)
    else:
        scale = max_bit_value // max_value
        inv_scale = 1.0 / float(scale)

    return unscaled * inv_scale


def read_vector_fixed_normal(reader: 'FBitReader') -> Optional[FVector]:
    """FVector_NetQuantizeNormal::NetSerialize → SerializeFixedVector<1, 16>"""
    if reader.get_bits_left() < 48:
        return None
    return FVector(
        read_fixed_compressed_float(reader, 1, 16),
        read_fixed_compressed_float(reader, 1, 16),
        read_fixed_compressed_float(reader, 1, 16),
    )


# ---------------------------------------------------------------------------
# Compressed rotators
# ---------------------------------------------------------------------------

def read_rotation_compressed_byte(reader: 'FBitReader') -> Optional[FRotator]:
    """TRotator<double>::SerializeCompressed (ByteComponents).

    Per component: 1-bit nonzero flag + uint8 if set.
    Decode: value * (360.0 / 256.0).
    """
    components = []
    for _ in range(3):
        if reader.get_bits_left() < 1:
            return None
        if reader.read_bit():
            if reader.get_bits_left() < 8:
                return None
            components.append(reader.read_byte() * (360.0 / 256.0))
        else:
            components.append(0.0)
    return FRotator(*components)


# ---------------------------------------------------------------------------
# FRepMovement
# ---------------------------------------------------------------------------

_VEL_MAG_SQ_MAX = 1e10  # 100k cm/s squared — fallback trigger for rotation mode


def read_rep_movement(
    reader: 'FBitReader',
    rotation_short: Optional[bool] = None,
    engine_ver: int = ENGINE_NET_VER_CURRENT,
) -> Optional[dict]:
    """FRepMovement::NetSerialize

    ERotatorQuantization is CDO-dependent and not on the wire.
    When rotation_short is None (default), both modes are tried:
    ByteComponents first, then ShortComponents if the resulting
    LinearVelocity magnitude is implausible
    """
    b_server_frame_supported = _ver_check(engine_ver, ENGINE_NET_VER_REP_MOVE_SERVER_FRAME_AND_HANDLE)

    flag_bits = 4 if b_server_frame_supported else 2
    if reader.get_bits_left() < flag_bits:
        return None

    flags = reader.serialize_bits(flag_bits)[0] & ((1 << flag_bits) - 1)
    b_simulated_physics_sleep = bool(flags & 1)
    b_rep_physics = bool(flags & 2)
    has_server_frame = bool(flags & 4) and b_server_frame_supported
    has_server_physics_handle = bool(flags & 8) and b_server_frame_supported

    location = read_quantized_vector(reader, 100, engine_ver)
    if location is None:
        return None

    candidates = [rotation_short] if rotation_short is not None else [False, True]
    checkpoint = reader.get_pos_bits()

    rotation = linear_velocity = None
    for is_short in candidates:
        reader.set_pos_bits(checkpoint)
        rot = (read_rotation_compressed_short if is_short else read_rotation_compressed_byte)(reader)
        if rot is None:
            continue
        vel = read_quantized_vector(reader, 1, engine_ver)
        if vel is None:
            continue
        if vel.x * vel.x + vel.y * vel.y + vel.z * vel.z <= _VEL_MAG_SQ_MAX:
            rotation, linear_velocity = rot, vel
            break

    if rotation is None:
        return None

    result = {
        'bSimulatedPhysicsSleep': b_simulated_physics_sleep,
        'Location': location,
        'Rotation': rotation,
        'LinearVelocity': linear_velocity,
    }

    if b_rep_physics:
        angular_velocity = read_quantized_vector(reader, 1, engine_ver)
        if angular_velocity is None:
            return None
        result['AngularVelocity'] = angular_velocity

    if has_server_frame:
        result['ServerFrame'] = reader.read_uint32_packed()

    if has_server_physics_handle:
        result['ServerPhysicsHandle'] = reader.read_uint32_packed()

    if _ver_check(engine_ver, ENGINE_NET_VER_REP_MOVE_OPTIONAL_ACCELERATION):
        if reader.get_bits_left() < 1:
            return None
        if reader.read_bit():
            acceleration = read_quantized_vector(reader, 1, engine_ver)
            if acceleration is None:
                return None
            result['Acceleration'] = acceleration

    return result


# ---------------------------------------------------------------------------
# Spawn info (ConditionallySerializeQuantizedVector)
# ---------------------------------------------------------------------------

def read_spawn_quantized_vector(reader: 'FBitReader', engine_ver: int = ENGINE_NET_VER_CURRENT) -> Optional[FVector]:
    """ConditionallySerializeQuantizedVector — spawn info vector.

    1-bit bShouldSerialize flag. If not set, vector is default (not serialized).

    v13+ (OptionallyQuantizeSpawnInfo):
      1-bit bShouldQuantize flag.
      If quantized: FVector_NetQuantize10 (ReadQuantizedVector, scale=10).
      If not: raw FVector (version-aware double/float).
    Older:
      Always quantized (no bShouldQuantize bit on wire).
    """
    if reader.get_bits_left() < 1:
        return None

    if not reader.read_bit():  # bShouldSerialize
        return None

    if engine_ver < ENGINE_NET_VER_OPTIONALLY_QUANTIZE_SPAWN_INFO:
        return read_quantized_vector(reader, scale=10, engine_ver=engine_ver)

    if reader.get_bits_left() < 1:
        return None

    if reader.read_bit():  # bShouldQuantize
        return read_quantized_vector(reader, scale=10, engine_ver=engine_ver)

    return read_vector_double(reader, engine_ver=engine_ver)


# ---------------------------------------------------------------------------
# FPredictionKey
# ---------------------------------------------------------------------------

def read_prediction_key(reader: 'FBitReader', engine_ver: int = ENGINE_NET_VER_CURRENT) -> dict:
    """FPredictionKey::NetSerialize — version-aware."""
    valid = reader.read_bit()

    # ver < PredictionKeyBaseNotReplicated: 1-bit HasBaseKey (if valid)
    has_base_key = False
    if engine_ver < ENGINE_NET_VER_PREDICTION_KEY_BASE_NOT_REPLICATED and valid:
        has_base_key = bool(reader.read_bit())

    server_initiated = reader.read_bit()

    current = 0
    base = 0
    if valid:
        current = reader.read_int16()
        if has_base_key:
            base = reader.read_int16()

    return {'Current': current, 'bIsServerInitiated': bool(server_initiated)}


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def _round_to_int(value: float) -> int:
    """Round-to-nearest, ties away from zero"""
    if value >= 0.0:
        return int(value + 0.5)
    return -int((-value) + 0.5)


def compress_axis_to_short(angle: float) -> int:
    """FRotator::CompressAxisToShort."""
    return _round_to_int(float(angle) * (65536.0 / 360.0)) & 0xFFFF


def compress_axis_to_byte(angle: float) -> int:
    """FRotator::CompressAxisToByte."""
    return _round_to_int(float(angle) * (256.0 / 360.0)) & 0xFF


def write_rotator_compressed_short(writer: 'FBitWriter', pitch: float, yaw: float, roll: float) -> None:
    """TRotator::SerializeCompressedShort — conditional 16-bit per component."""
    for angle in (pitch, yaw, roll):
        compressed = compress_axis_to_short(angle)
        writer.write_bit(compressed != 0)
        if compressed != 0:
            writer.write_uint16(compressed)


def write_quantized_vector_scaled(writer: 'FBitWriter', x: float, y: float, z: float, scale: int) -> None:
    """WriteQuantizedVector (v23+) with the given integer scale."""
    sx = _round_to_int(float(x) * float(scale))
    sy = _round_to_int(float(y) * float(scale))
    sz = _round_to_int(float(z) * float(scale))
    max_abs = max(abs(sx), abs(sy), abs(sz))
    # GetBitsNeeded returns at least 1 (sign bit).
    n_bits = max(1, min(63, max_abs.bit_length() + 1))

    # Header: low 6 bits = component bit count, bit 6 = bUseScaledValue.
    header = n_bits | 0x40
    writer.serialize_int(header, 128)

    def _write_signed(value: int) -> None:
        raw = (1 << n_bits) + value if value < 0 else value
        writer.serialize_bits(raw.to_bytes((n_bits + 7) // 8, "little"), n_bits)

    _write_signed(sx)
    _write_signed(sy)
    _write_signed(sz)