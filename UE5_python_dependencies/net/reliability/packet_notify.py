# net/reliability/packet_notify.py
"""FNetPacketNotify - drives sequence numbers, acknowledgments and notifications."""
from __future__ import annotations

from collections import deque
from typing import Callable, Optional, TYPE_CHECKING
from dataclasses import dataclass

from constants import MAX_SEQUENCE_HISTORY_LENGTH, BITS_PER_WORD, SEQUENCE_NUMBER_BITS, HISTORY_WORD_COUNT_BITS
from net.reliability.sequence_number import SequenceNumber
from net.reliability.sequence_history import SequenceHistory

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader
    from serialization.bit_writer import FBitWriter


@dataclass(slots=True)
class FNotificationHeader:
    history: SequenceHistory
    history_word_count: int
    seq: SequenceNumber
    acked_seq: SequenceNumber


@dataclass(slots=True)
class FSentAckData:
    out_seq: SequenceNumber
    in_ack_seq: SequenceNumber


# ---------------------------------------------------------------------------
# FPackedHeader — internal packed header
# Layout: [Seq : SeqBits] [AckedSeq : SeqBits] [HistoryWordCount-1 : HistBits]
# ---------------------------------------------------------------------------
class FPackedHeader:
    SeqBits = SEQUENCE_NUMBER_BITS
    HistBits = HISTORY_WORD_COUNT_BITS
    TotalBits = SeqBits * 2 + HistBits
    UseUint64 = TotalBits > 32
    SeqMask = (1 << SeqBits) - 1
    HistMask = (1 << HistBits) - 1
    AckSeqShift = HistBits
    SeqShift = AckSeqShift + SeqBits

    @staticmethod
    def pack(seq: SequenceNumber, acked_seq: SequenceNumber, history_word_count: int) -> int:
        packed = 0
        packed |= (int(seq) & FPackedHeader.SeqMask) << FPackedHeader.SeqShift
        packed |= (int(acked_seq) & FPackedHeader.SeqMask) << FPackedHeader.AckSeqShift
        packed |= max(0, history_word_count - 1) & FPackedHeader.HistMask
        return packed

    @staticmethod
    def get_seq(packed: int) -> SequenceNumber:
        return SequenceNumber((packed >> FPackedHeader.SeqShift) & FPackedHeader.SeqMask)

    @staticmethod
    def get_acked_seq(packed: int) -> SequenceNumber:
        return SequenceNumber((packed >> FPackedHeader.AckSeqShift) & FPackedHeader.SeqMask)

    @staticmethod
    def get_history_word_count(packed: int) -> int:
        return (packed & FPackedHeader.HistMask) + 1


# ---------------------------------------------------------------------------
# FNetPacketNotify
# ---------------------------------------------------------------------------
class FNetPacketNotify:
    SequenceNumberBits = SEQUENCE_NUMBER_BITS
    MaxSequenceHistoryLength = MAX_SEQUENCE_HISTORY_LENGTH

    __slots__ = (
        'in_seq_history', 'in_seq', 'in_ack_seq', 'in_ack_seq_ack',
        'out_seq', 'out_ack_seq',
        'written_history_word_count', 'written_in_ack_seq', 'waiting_for_flush_seq_ack',
        '_ack_record',
    )

    def __init__(self):
        self.in_seq_history = SequenceHistory()
        self.in_seq = SequenceNumber(0)
        self.in_ack_seq = SequenceNumber(0)
        self.in_ack_seq_ack = SequenceNumber(0)

        self.out_seq = SequenceNumber(0)
        self.out_ack_seq = SequenceNumber(0)

        self.written_history_word_count = 0
        self.written_in_ack_seq = SequenceNumber(0)
        self.waiting_for_flush_seq_ack = SequenceNumber(0)

        self._ack_record: deque[FSentAckData] = deque()

    def init(self, initial_in_seq: SequenceNumber, initial_out_seq: SequenceNumber) -> None:
        self.in_seq_history.reset()
        self.in_seq = SequenceNumber(initial_in_seq.value - 1)
        self.in_ack_seq = SequenceNumber(initial_in_seq.value - 1)
        self.in_ack_seq_ack = SequenceNumber(initial_in_seq.value - 1)
        self.out_seq = initial_out_seq
        self.out_ack_seq = SequenceNumber(initial_out_seq.value - 1)
        self.waiting_for_flush_seq_ack = self.out_ack_seq
        self._ack_record.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ack_seq(self, seq: SequenceNumber) -> None:
        """Mark seq as received. Called from connection after processing bunches."""
        self._ack_seq(seq, True)

    def nak_seq(self, seq: SequenceNumber) -> None:
        """Explicitly mark seq as not received."""
        self._ack_seq(seq, False)

    def commit_and_increment_out_seq(self) -> SequenceNumber:
        """Increment outgoing seq number and commit data. Returns the NEW seq."""
        self._ack_record.append(FSentAckData(
            out_seq=self.out_seq,
            in_ack_seq=self.written_in_ack_seq,
        ))
        self.written_history_word_count = 0
        self.out_seq += 1
        return self.out_seq

    def get_sequence_delta(self, notification_data: FNotificationHeader) -> int:
        if (notification_data.seq > self.in_seq and
            notification_data.acked_seq >= self.out_ack_seq and
                self.out_seq > notification_data.acked_seq):
            return SequenceNumber.diff(notification_data.seq, self.in_seq)
        return 0

    def update(self, notification_data: FNotificationHeader,
               ack_callback: Optional[Callable[[SequenceNumber, bool], None]] = None) -> int:
        in_seq_delta = self.get_sequence_delta(notification_data)

        if in_seq_delta > 0:
            self._process_received_acks(notification_data, ack_callback)
            return self._internal_update(notification_data, in_seq_delta)

        return 0

    # ------------------------------------------------------------------
    # Header serialization
    # ------------------------------------------------------------------

    def write_header(self, writer: FBitWriter, b_refresh: bool = False) -> bool:
        current_history_word_count = max(
            1,
            min(
                (self.get_current_sequence_history_length() + SequenceHistory.BitsPerWord - 1) // SequenceHistory.BitsPerWord,
                SequenceHistory.WordCount,
            ),
        )

        if b_refresh and current_history_word_count > self.written_history_word_count:
            return False

        self.written_history_word_count = self.written_history_word_count if b_refresh else current_history_word_count
        self.written_in_ack_seq = self.in_ack_seq

        packed = FPackedHeader.pack(self.out_seq, self.in_ack_seq, self.written_history_word_count)
        if FPackedHeader.UseUint64:
            writer.write_uint64(packed)
        else:
            writer.write_uint32(packed)

        self.in_seq_history.write(writer, self.written_history_word_count)
        return True

    def read_header(self, reader: FBitReader) -> Optional[FNotificationHeader]:
        packed = reader.read_uint64() if FPackedHeader.UseUint64 else reader.read_uint32()

        data = FNotificationHeader(
            history=SequenceHistory(),
            history_word_count=FPackedHeader.get_history_word_count(packed),
            seq=FPackedHeader.get_seq(packed),
            acked_seq=FPackedHeader.get_acked_seq(packed),
        )

        data.history.read(reader, data.history_word_count)
        return data

    # ------------------------------------------------------------------
    # Getters
    # ------------------------------------------------------------------

    def get_in_seq(self) -> SequenceNumber:
        return self.in_seq

    def get_in_ack_seq(self) -> SequenceNumber:
        return self.in_ack_seq

    def get_out_seq(self) -> SequenceNumber:
        return self.out_seq

    def get_out_ack_seq(self) -> SequenceNumber:
        return self.out_ack_seq

    def get_in_seq_history(self) -> SequenceHistory:
        return self.in_seq_history

    def can_send(self) -> bool:
        next_out_seq = self.out_seq.increment_and_get()
        return next_out_seq >= self.out_ack_seq

    def is_sequence_window_full(self, safety_margin: int = 0) -> bool:
        sequence_length = SequenceNumber.diff(self.out_seq, self.out_ack_seq)
        return (sequence_length > self.MaxSequenceHistoryLength or
                safety_margin >= self.MaxSequenceHistoryLength or
                sequence_length > (self.MaxSequenceHistoryLength - safety_margin))

    def get_current_sequence_history_length(self) -> int:
        if self.in_ack_seq >= self.in_ack_seq_ack:
            return min(
                SequenceNumber.diff(self.in_ack_seq, self.in_ack_seq_ack),
                SequenceHistory.Size,
            )
        return SequenceHistory.Size

    def is_waiting_for_sequence_history_flush(self) -> bool:
        return self.waiting_for_flush_seq_ack > self.out_ack_seq

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _ack_seq(self, acked_seq: SequenceNumber, is_ack: bool) -> None:
        """Fill history from InAckSeq+1 to acked_seq. Only the last entry gets is_ack."""
        while acked_seq > self.in_ack_seq:
            self.in_ack_seq += 1
            report_acked = is_ack if (self.in_ack_seq == acked_seq) else False
            self.in_seq_history.add_delivery_status(report_acked)

    def _will_sequence_fit_in_history(self, seq: SequenceNumber) -> bool:
        if seq >= self.in_ack_seq_ack:
            return SequenceNumber.diff(seq, self.in_ack_seq_ack) <= SequenceHistory.Size
        return False

    def _get_has_unacknowledged_acks(self) -> bool:
        length = self.get_current_sequence_history_length()
        for i in range(length):
            if self.in_seq_history.is_delivered(i):
                return True
        return False

    def _set_wait_for_sequence_history_flush(self) -> None:
        self.waiting_for_flush_seq_ack = self.out_seq

    def _update_in_ack_seq_ack(self, ack_count: int, acked_seq: SequenceNumber) -> SequenceNumber:
        if ack_count <= len(self._ack_record):
            for _ in range(ack_count - 1):
                self._ack_record.popleft()

            ack_data = self._ack_record.popleft()

            if ack_data.out_seq == acked_seq:
                return ack_data.in_ack_seq

        # Pessimistic fallback
        return SequenceNumber(acked_seq.value - self.MaxSequenceHistoryLength)

    def _process_received_acks(self, notification_data: FNotificationHeader,
                               ack_callback: Optional[Callable[[SequenceNumber, bool], None]]) -> None:
        if notification_data.acked_seq > self.out_ack_seq:
            ack_count = SequenceNumber.diff(notification_data.acked_seq, self.out_ack_seq)

            new_in_ack_seq_ack = self._update_in_ack_seq_ack(ack_count, notification_data.acked_seq)
            if new_in_ack_seq_ack > self.in_ack_seq_ack:
                self.in_ack_seq_ack = new_in_ack_seq_ack

            current_ack = SequenceNumber(self.out_ack_seq.value + 1)
            history_bits = notification_data.history_word_count * BITS_PER_WORD

            while ack_count > history_bits:
                ack_count -= 1
                if ack_callback:
                    ack_callback(current_ack, False)
                current_ack = current_ack.increment_and_get()

            while ack_count > 0:
                ack_count -= 1
                is_delivered = notification_data.history.is_delivered(ack_count)
                if ack_callback:
                    ack_callback(current_ack, is_delivered)
                current_ack = current_ack.increment_and_get()

            self.out_ack_seq = notification_data.acked_seq

            if self.out_ack_seq > self.waiting_for_flush_seq_ack:
                self.waiting_for_flush_seq_ack = self.out_ack_seq

    def _internal_update(self, notification_data: FNotificationHeader, in_seq_delta: int) -> int:
        if (not self.is_waiting_for_sequence_history_flush() and
                not self._will_sequence_fit_in_history(notification_data.seq)):
            if self._get_has_unacknowledged_acks():
                self._set_wait_for_sequence_history_flush()
            else:
                self.in_ack_seq_ack = SequenceNumber(notification_data.seq.value - 1)

        if not self.is_waiting_for_sequence_history_flush():
            self.in_seq = notification_data.seq
            return in_seq_delta
        else:
            new_in_seq_to_ack = SequenceNumber(notification_data.seq.value)

            if (not self._will_sequence_fit_in_history(notification_data.seq) and
                    self._get_has_unacknowledged_acks()):
                new_in_seq_to_ack = SequenceNumber(
                    self.in_ack_seq_ack.value +
                    (self.MaxSequenceHistoryLength - self.get_current_sequence_history_length())
                )

            if new_in_seq_to_ack >= self.in_seq:
                adjusted_delta = SequenceNumber.diff(new_in_seq_to_ack, self.in_seq)
                self.in_seq = new_in_seq_to_ack
                self._ack_seq(new_in_seq_to_ack, False)
                return adjusted_delta
            else:
                return 0
