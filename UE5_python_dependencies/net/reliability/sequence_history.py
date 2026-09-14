# net/reliability/sequence_history.py
"""TSequenceHistory - bit buffer for packet delivery tracking."""
from __future__ import annotations

from typing import TYPE_CHECKING

from constants import MAX_SEQUENCE_HISTORY_LENGTH, BITS_PER_WORD, HISTORY_WORDS

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader
    from serialization.bit_writer import FBitWriter


class SequenceHistory:
    __slots__ = ('_data',)

    Size = MAX_SEQUENCE_HISTORY_LENGTH
    BitsPerWord = BITS_PER_WORD
    WordCount = HISTORY_WORDS

    def __init__(self):
        self._data = [0] * self.WordCount

    def reset(self) -> None:
        self._data = [0] * self.WordCount

    def is_delivered(self, index: int) -> bool:
        if index < 0 or index >= self.Size:
            return False
        word_idx = index // self.BitsPerWord
        bit_idx = index & (self.BitsPerWord - 1)
        return bool(self._data[word_idx] & (1 << bit_idx))

    def add_delivery_status(self, is_delivered: bool) -> None:
        carry = 1 if is_delivered else 0
        for i in range(self.WordCount):
            old_carry = carry
            carry = (self._data[i] >> 31) & 1
            self._data[i] = ((self._data[i] << 1) | old_carry) & 0xFFFFFFFF

    def write(self, writer: FBitWriter, num_words: int) -> None:
        num_words = min(num_words, self.WordCount)
        for i in range(num_words):
            writer.write_uint32(self._data[i])

    def read(self, reader: FBitReader, num_words: int) -> None:
        num_words = min(num_words, self.WordCount)
        for i in range(num_words):
            self._data[i] = reader.read_uint32()

    def get_word(self, index: int) -> int:
        if 0 <= index < self.WordCount:
            return self._data[index]
        return 0

    def set_word(self, index: int, value: int) -> None:
        if 0 <= index < self.WordCount:
            self._data[index] = value & 0xFFFFFFFF

    def get_data(self) -> list:
        return list(self._data)

    def set_data(self, data: list) -> None:
        for i in range(min(len(data), self.WordCount)):
            self._data[i] = data[i] & 0xFFFFFFFF

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SequenceHistory):
            return NotImplemented
        return self._data == other._data

    def __repr__(self) -> str:
        return f"SequenceHistory({self._data})"
