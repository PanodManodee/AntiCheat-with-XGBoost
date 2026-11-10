# serialization/bit_writer.py
from __future__ import annotations
from math import ceil, log2
import struct
from serialization.bit_util import FBitUtil


class BitWriterError(RuntimeError):
    pass


class FBitWriter:
    __slots__ = ('_data', '_num_bits', '_max_bits', '_allow_resize', '_error')

    def __init__(self, max_bits: int = 0, allow_resize: bool = False):
        self._data = bytearray((max_bits + 7) // 8)
        self._num_bits = 0
        self._max_bits = max_bits
        self._allow_resize = allow_resize
        self._error = False

    @property
    def num_bits(self) -> int:
        return self._num_bits

    @property
    def num_bytes(self) -> int:
        return (self._num_bits + 7) // 8

    def get_buffer(self) -> bytes:
        if self._error:
            raise BitWriterError("BitWriter in error state")
        return bytes(self._data[:self.num_bytes])

    def _ensure_capacity(self, length_bits: int) -> bool:
        if self._num_bits + length_bits > self._max_bits:
            if self._allow_resize:
                self._max_bits = max(self._max_bits * 2, self._num_bits + length_bits)
                byte_max = (self._max_bits + 7) >> 3
                if byte_max > len(self._data):
                    self._data.extend(b"\x00" * (byte_max - len(self._data)))
                return True
            return False
        return True

    def write_bit(self, value: int | bool) -> None:
        if not self._ensure_capacity(1):
            self._error = True
            raise BitWriterError("BitWriter overflow (1 bit)")
        if value:
            self._data[self._num_bits >> 3] |= 1 << (self._num_bits & 7)
        self._num_bits += 1

    def write_uint32(self, value: int) -> None:
        self._write_bits(struct.pack("<I", value), 32)

    def write_int32(self, value: int) -> None:
        self._write_bits(struct.pack("<i", value), 32)

    def write_uint64(self, value: int) -> None:
        self._write_bits(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF), 64)

    def write_int_wrapped(self, value: int, value_max: int) -> None:
        if value_max < 2:
            raise ValueError("value_max must be >= 2")

        length_bits = int(ceil(log2(value_max)))
        value &= (1 << length_bits) - 1
        num_bytes = (length_bits + 7) // 8
        self._write_bits(value.to_bytes(num_bytes, "little"), length_bits)

    def write_float(self, value: float) -> None:
        self._write_bits(struct.pack("<f", float(value)), 32)

    def write_uint16(self, value: int) -> None:
        self._write_bits(struct.pack("<H", int(value) & 0xFFFF), 16)

    def write_int16(self, value: int) -> None:
        self._write_bits(struct.pack("<H", int(value) & 0xFFFF), 16)

    def write_double(self, value: float) -> None:
        self._write_bits(struct.pack("<d", value), 64)

    def write_align(self) -> None:
        self._num_bits = (self._num_bits + 7) & ~0x07

    def serialize_fstring(self, s: str | None) -> None:
        if s is None or s == '':
            self.write_int32(0 if s is None else 1)
            if s == '':
                self._write_bits(b'\x00', 8)
            return

        encoded = s.encode('utf-8') + b'\x00'
        self.write_int32(len(encoded))
        self.serialize(encoded)

    def serialize(self, src: bytes) -> None:
        self._write_bits(src, len(src) * 8)

    def serialize_bits(self, src: bytes, length_bits: int) -> None:
        self._write_bits(src, length_bits)

    def serialize_int(self, value: int, value_max: int) -> None:
        if value_max < 2:
            raise ValueError("value_max must be >= 2")

        value = min(value, value_max - 1)
        new_value = 0
        mask = 1
        data = self._data
        while (new_value + mask) < value_max and mask != 0:
            if not self._ensure_capacity(1):
                self._error = True
                raise BitWriterError("BitWriter overflow")
            if value & mask:
                new_value |= mask
                data[self._num_bits >> 3] |= 1 << (self._num_bits & 7)
            self._num_bits += 1
            mask <<= 1

    def write_uint32_packed(self, value: int, min_bytes: int = 1) -> None:
        bytes_as_words = []
        v = value & 0xFFFFFFFF
        first = True
        while first or v != 0:
            first = False
            chunk = v & 0x7F
            v >>= 7
            bytes_as_words.append((chunk << 1) | (1 if v != 0 else 0))

        while len(bytes_as_words) < min_bytes:
            if bytes_as_words:
                bytes_as_words[-1] |= 1
            bytes_as_words.append(0)

        byte_count = len(bytes_as_words)
        length_bits = byte_count << 3

        if not self._ensure_capacity(length_bits):
            self._error = True
            raise BitWriterError("BitWriter overflow")

        needed_bytes = (self._num_bits + length_bits + 7) >> 3
        data = self._data
        if needed_bytes > len(data):
            data.extend(b"\x00" * (needed_bytes - len(data)))

        bit_used = self._num_bits & 7
        if bit_used == 0:
            byte_pos = self._num_bits >> 3
            for i, word in enumerate(bytes_as_words):
                data[byte_pos + i] = word
        else:
            bit_left = 8 - bit_used
            dest_mask0 = (1 << bit_used) - 1
            dest_mask1 = dest_mask0 ^ 0xFF
            dest_idx = self._num_bits >> 3
            for word in bytes_as_words:
                data[dest_idx] = (data[dest_idx] & dest_mask0) | ((word << bit_used) & 0xFF)
                dest_idx += 1
                data[dest_idx] = (data[dest_idx] & dest_mask1) | (word >> bit_left)

        self._num_bits += length_bits

    def write_uint64_packed(self, value: int) -> None:
        bytes_as_words = []
        v = value & 0xFFFFFFFFFFFFFFFF
        first = True
        while first or v != 0:
            first = False
            chunk = v & 0x7F
            v >>= 7
            bytes_as_words.append((chunk << 1) | (1 if v != 0 else 0))

        byte_count = len(bytes_as_words)
        length_bits = byte_count << 3

        if not self._ensure_capacity(length_bits):
            self._error = True
            raise BitWriterError("BitWriter overflow")

        needed_bytes = (self._num_bits + length_bits + 7) >> 3
        data = self._data
        if needed_bytes > len(data):
            data.extend(b"\x00" * (needed_bytes - len(data)))

        bit_used = self._num_bits & 7
        if bit_used == 0:
            byte_pos = self._num_bits >> 3
            for i, word in enumerate(bytes_as_words):
                data[byte_pos + i] = word
        else:
            bit_left = 8 - bit_used
            dest_mask0 = (1 << bit_used) - 1
            dest_mask1 = dest_mask0 ^ 0xFF
            dest_idx = self._num_bits >> 3
            for word in bytes_as_words:
                data[dest_idx] = (data[dest_idx] & dest_mask0) | ((word << bit_used) & 0xFF)
                dest_idx += 1
                data[dest_idx] = (data[dest_idx] & dest_mask1) | (word >> bit_left)

        self._num_bits += length_bits

    def _write_bits(self, src: bytes, length_bits: int) -> None:
        if length_bits == 0:
            return

        if not self._ensure_capacity(length_bits):
            self._error = True
            raise BitWriterError(f"BitWriter overflow (tried {length_bits} bits, remaining {self._max_bits - self._num_bits})")

        needed_bytes = (self._num_bits + length_bits + 7) >> 3
        if needed_bytes > len(self._data):
            self._data.extend(b"\x00" * (needed_bytes - len(self._data)))

        # Fast path: byte-aligned position
        if (self._num_bits & 7) == 0:
            byte_pos = self._num_bits >> 3
            num_full_bytes = length_bits >> 3
            if num_full_bytes:
                self._data[byte_pos:byte_pos + num_full_bytes] = src[:num_full_bytes]
            tail = length_bits & 7
            if tail:
                self._data[byte_pos + num_full_bytes] = src[num_full_bytes] & ((1 << tail) - 1)
            self._num_bits += length_bits
            return

        FBitUtil.app_bits_cpy(self._data, self._num_bits, src, 0, length_bits)
        self._num_bits += length_bits
