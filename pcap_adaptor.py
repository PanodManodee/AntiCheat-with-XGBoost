# pcap_adaptor.py
"""Decode UE5 network packets from a .pcap offline using the UE5_python_client
network implementation (FBitReader, FNetPacketNotify, StatelessConnectHandler,
NetConnection bunch parsing).

Reuses the vendored UE5 client's bit-level serialization and protocol parsing
to extract the handler prefix, handshake fields, packet header (seq/ack/history)
and per-bunch/channel payload together with standard packet metadata.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import IP, UDP

BASE_DIR = Path(__file__).resolve().parent
CLIENT_DIR = BASE_DIR / "UE5_python_client" / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from serialization.bit_reader import FBitReader, BitReaderError
from serialization.bit_util import FBitUtil
from net.handlers.stateless_connect import (
    StatelessConnectHandlerComponent,
    HandshakePacketType,
)
from net.connection import NetConnection
from net.error_reporter import PARSE_EXCEPTIONS
from app_config import LOCAL_NETWORK_VERSION


DEFAULT_SERVER_PORT = 7777
DEFAULT_OUTPUT = "pcap_adaptor_out.csv"

HANDSHAKE_NAMES = {int(v): name for name, v in HandshakePacketType.__members__.items()}

# Canonical output schema. Frames are reindexed to these column orders (and
# missing cells blanked) before being written, so appending one-file CSV
# fragments can never drift the header/row alignment.
PACKET_COLUMNS = [
    "file", "packet_no", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "packet_length", "ttl", "sport", "dport", "client_ip", "client_port",
    "flow", "payload_len", "payload_hex", "error", "is_handshake",
    "travel_count", "cached_client_id",
    "packet_type", "min_version", "handshake_version", "restarted",
    "network_version", "runtime_features", "secret_id", "timestamp_f",
    "cookie_hex", "client_id",
    "bunch_count", "channels", "seq", "acked_seq", "history_word_count",
    "history_words", "has_packet_info", "jitter_clock_ms",
    "has_server_frame_time", "server_frame_time",
    "bunch_parse_error", "short_packet",
]

BUNCH_COLUMNS = [c for c in PACKET_COLUMNS if c != "payload_hex"] + [
    "bunch_no", "ch_index", "ch_name", "reliable", "open", "close", "partial",
    "partial_initial", "partial_final", "ch_sequence", "has_package_map_exports",
    "has_must_be_mapped_guids", "payload_bits",
]


def _canonicalize(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Normalise a frame to the canonical schema for CSV output.

    Reindex to the fixed column order and blank out missing cells so that
    per-file fragments can be appended without header/row misalignment.
    """
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    df = df[columns].astype(object).fillna("")
    return df[columns]


class PcapAdaptor:
    """Offline UE5 pcap decoder reusing the UE5 network implementation."""

    def __init__(self, server_port: int = DEFAULT_SERVER_PORT):
        self.server_port = server_port
        self._rows: list[dict] = []
        self._bunch_rows: list[dict] = []
        self._stateless = StatelessConnectHandlerComponent(
            CachedClientID=0,
            LocalNetworkVersion=LOCAL_NETWORK_VERSION,
        )
        # Per-client connection state, keyed by (direction, client addr port).
        # A single pcap may contain several concurrent clients hitting one
        # server, each with its own sequence space — mixing them corrupts
        # reliable-sequence/channel tracking.
        self._connections: dict[tuple, NetConnection] = {}
        self._client_id: int | None = None
        self._network_version: int | None = None

    @staticmethod
    def _client_key(to_server: bool, ip: str, port: int) -> tuple:
        if to_server:
            return ("cs", ip, port)
        return ("sc", ip, port)

    def _get_conn(self, key: tuple) -> NetConnection:
        conn = self._connections.get(key)
        if conn is not None:
            return conn

        # The live client seeds in/out seq from the handshake ACK cookie.
        # For offline analysis the packet header is read directly, so an
        # arbitrary consistent seed is sufficient for stateful bunch parsing.
        conn = NetConnection(
            cached_client_id=self._client_id or 0,
            initial_in_seq=0,
            initial_out_seq=0,
            local_network_version=self._network_version or LOCAL_NETWORK_VERSION,
        )
        conn.set_handlers([self._stateless])
        self._connections[key] = conn
        return conn

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    def _decode(self, payload: bytes, to_server: bool, key: tuple):
        """Decode a single UDP payload. Returns a dict of common fields."""
        info: dict = {
            "flow": "cs" if to_server else "sc",
            "payload_len": len(payload),
            "payload_hex": payload.hex(),
            "error": "",
            "is_handshake": False,
        }

        if not payload:
            info["error"] = "empty"
            return info

        try:
            # Strip outer terminator (Handler->Outgoing result end).
            outer_bits = FBitUtil.strip_trailing_one(payload)
            if outer_bits <= 0:
                info.update(self._decode_handshake(payload))
                return info

            reader = FBitReader(payload, num_bits=outer_bits)

            # StatelessConnect: read 6-bit handler prefix directly from the
            # raw reader (before Incoming mutates Cached global/client id).
            pref_reader = FBitReader(payload, num_bits=outer_bits)
            travel_count = pref_reader.read_int(4)
            cached_client_id = pref_reader.read_int(8)
            b_handshake = pref_reader.read_bit()

            info["travel_count"] = travel_count
            info["cached_client_id"] = cached_client_id

            if b_handshake:
                info.update(self._decode_handshake(payload))
                return info

            # Data packet: process handler prefix via Incoming().
            try:
                inner_reader = self._stateless.Incoming(reader)
            except PARSE_EXCEPTIONS as exc:
                info["error"] = f"handler_incoming: {exc}"
                return info

            inner_data = inner_reader.get_buffer()
            inner_bits = FBitUtil.strip_trailing_one(inner_data)
            if inner_bits <= 0:
                info["error"] = "no_inner_term"
                return info

            packet_reader = FBitReader(inner_data, num_bits=inner_bits)

            conn = self._get_conn(key)
            info.update(self._decode_packet(conn, packet_reader))
            return info

        except PARSE_EXCEPTIONS as exc:
            info["error"] = f"{type(exc).__name__}: {exc}"
            return info
        except Exception as exc:  # noqa: BLE001 - keep per-packet robustness
            info["error"] = f"{type(exc).__name__}: {exc}"
            return info

    def _decode_handshake(self, payload: bytes) -> dict:
        try:
            hs = self._stateless.parse_handshake_packet(payload)
        except Exception as exc:  # noqa: BLE001
            return {"is_handshake": True, "packet_type": "?",
                    "error": f"handshake_parse: {exc}"}

        packet_type = HANDSHAKE_NAMES.get(hs.PacketType, str(hs.PacketType))

        if packet_type == "Ack":
            self._client_id = hs.CachedClientID
            self._network_version = hs.LocalNetworkVersion or self._network_version

        return {
            "is_handshake": True,
            "packet_type": packet_type,
            "min_version": hs.MinSupportedHandshakeVersion,
            "handshake_version": hs.HandshakeVersion,
            "restarted": hs.bRestartedHandshake,
            "network_version": hs.LocalNetworkVersion or None,
            "runtime_features": hs.RuntimeFeatures or None,
            "secret_id": hs.SecretId,
            "timestamp_f": hs.Timestamp,
            "cookie_hex": hs.Cookie.hex(),
            "client_id": hs.CachedClientID or None,
        }

    def _decode_packet(self, conn: NetConnection, reader: FBitReader) -> dict:
        info: dict = {"is_handshake": False, "bunch_count": 0, "channels": "", "bunches": []}

        # Packet header (FNetPacketNotify): Seq / AckedSeq / History.
        header = conn.packet_notify.read_header(reader)
        if header is None:
            info["error"] = "bad_header"
            return info

        info["seq"] = header.seq.value
        info["acked_seq"] = header.acked_seq.value
        info["history_word_count"] = header.history_word_count
        history_words = header.history.get_data()[:header.history_word_count]
        info["history_words"] = [f"{w:08x}" for w in history_words]
        info["bunches"] = []

        if conn.local_network_version:
            try:
                b_has_packet_info = reader.read_bit()
                info["has_packet_info"] = b_has_packet_info
                if b_has_packet_info:
                    info["jitter_clock_ms"] = reader.read_int(1024)
                    b_has_frame = reader.read_bit()
                    info["has_server_frame_time"] = b_has_frame
                    if b_has_frame:
                        info["server_frame_time"] = reader.serialize_bits(8)[0]
            except BitReaderError:
                # Short packet: packet-info extends past the end of data.
                # Alignment is unknown, so stop bunch parsing here.
                info["short_packet"] = True
                return info
            except PARSE_EXCEPTIONS as exc:
                info["error"] = f"packet_info: {exc}"
                return info

        # Parse bunches (channel headers + payload lengths).
        bunch_count = 0
        try:
            while not reader.at_end() and reader.get_bits_left() >= 10:
                bunch = conn._parse_bunch_header(reader)
                conn._read_bunch_payload(reader, bunch)
                bunch_count += 1
                info["bunches"].append(self._bunch_to_dict(bunch))
        except PARSE_EXCEPTIONS as exc:
            info["bunch_parse_error"] = f"{type(exc).__name__}: {exc}"

        info["bunch_count"] = bunch_count
        info["channels"] = ",".join(str(c) for c in sorted({b["ch_index"] for b in info["bunches"]}))
        return info

    @staticmethod
    def _bunch_to_dict(bunch) -> dict:
        name = getattr(bunch, "ChName", None)
        return {
            "ch_index": bunch.ChIndex,
            "ch_name": getattr(name, "name", None) if name is not None else None,
            "reliable": bunch.bReliable,
            "open": bunch.bOpen,
            "close": bunch.bClose,
            "partial": bunch.bPartial,
            "partial_initial": getattr(bunch, "bPartialInitial", False),
            "partial_final": getattr(bunch, "bPartialFinal", False),
            "ch_sequence": getattr(bunch, "ChSequence", 0),
            "has_package_map_exports": bunch.bHasPackageMapExports,
            "has_must_be_mapped_guids": bunch.bHasMustBeMappedGUIDs,
            "payload_bits": bunch.num_bits if hasattr(bunch, "num_bits") else 0,
        }

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def process_file(self, pcap_path: str | Path) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
        """Process one pcap, returning (packet_df, bunch_df, counts).

        Rows are collected only for this file and released afterwards so that
        memory stays bounded regardless of dataset size.
        """
        pcap_path = Path(pcap_path)
        file_name = pcap_path.name
        packet_no = 0
        self._rows = []
        self._bunch_rows = []

        # UDP/IP packets captured for the server flow, buffered then processed
        # in strict chronological order (pcap files can contain reordered
        # packets, which would corrupt stateful sequence/channel parsing).
        captured: list[tuple[float, object]] = []

        with PcapReader(str(pcap_path)) as packets:
            for pkt in packets:
                if IP not in pkt or UDP not in pkt:
                    continue
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if self.server_port not in (sport, dport):
                    continue
                captured.append((float(pkt.time), pkt))

        captured.sort(key=lambda t: t[0])

        for _, pkt in captured:
            packet_no += 1

            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            to_server = dport == self.server_port
            payload = bytes(pkt[UDP].payload)

            key = self._client_key(to_server, pkt[IP].src, sport if to_server else dport)
            decoded = self._decode(payload, to_server, key)

            base = {
                "file": file_name,
                "packet_no": packet_no,
                "timestamp": float(pkt.time),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "src_port": sport,
                "dst_port": dport,
                "packet_length": len(pkt),
                "ttl": pkt[IP].ttl,
                "sport": sport,
                "dport": dport,
                "client_ip": pkt[IP].src if to_server else pkt[IP].dst,
                "client_port": sport if to_server else dport,
            }
            base.update(decoded)
            base.pop("bunches", None)
            self._rows.append(base)

            for i, b in enumerate(decoded.get("bunches", [])):
                row = dict(base)
                row.pop("bunches", None)
                row.pop("payload_hex", None)
                row["bunch_no"] = i
                row.update(b)
                self._bunch_rows.append(row)

        df = _canonicalize(pd.DataFrame(self._rows), PACKET_COLUMNS)
        bunch_df = _canonicalize(pd.DataFrame(self._bunch_rows), BUNCH_COLUMNS)
        counts = {
            "packets": len(df),
            "bunches": len(bunch_df),
            "handshake": 0,
            "data": 0,
            "errors": 0,
        }
        if not df.empty:
            hs = df["is_handshake"].fillna(False).astype(bool)
            err = df["error"].notna() & (df["error"] != "")
            counts["handshake"] = int(hs.sum())
            counts["data"] = int((~hs).sum())
            counts["errors"] = int(err.sum())
        return df, bunch_df, counts

    def get_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(self._rows)

    def get_bunch_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(self._bunch_rows)


def discover_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(f for f in path.rglob("**/*.pcap"))
        else:
            globbed = list(BASE_DIR.glob(p))
            files.extend(g for g in globbed if g.is_file())
    # Dedupe while preserving discovery order.
    seen: set[str] = set()
    ordered: list[Path] = []
    for f in files:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            ordered.append(f)
    return ordered


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Decode UE5 packets from a .pcap using the UE5 network implementation.")
    p.add_argument("input", nargs="*", default=["dataset"],
                   help="pcap file(s) or directory/glob to scan")
    p.add_argument("--output", default=DEFAULT_OUTPUT,
                   help="output CSV path (default: %(default)s)")
    p.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT,
                   help="UDP server port used to identify flows (default: %(default)s)")
    a = p.parse_args(argv)

    files = discover_files(a.input)
    if not files:
        print(f"No .pcap files found under {a.input}")
        return

    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    bunch_out = out.with_name(out.stem + "_bunches.csv")
    for path in (out, bunch_out):
        path.unlink(missing_ok=True)

    adaptor = PcapAdaptor(server_port=a.server_port)
    total_start = time.monotonic()
    total = {"packets": 0, "bunches": 0, "handshake": 0, "data": 0, "errors": 0}

    for idx, f in enumerate(files, start=1):
        start = time.monotonic()
        print(f"[{idx}/{len(files)}] Processing {f}...", flush=True)
        df, bunch_df, counts = adaptor.process_file(f)

        df.to_csv(out, mode="a", index=False,
                  header=(idx == 1 or out.stat().st_size == 0))
        if not bunch_df.empty:
            bunch_df.to_csv(bunch_out, mode="a", index=False,
                            header=(idx == 1 or not bunch_out.exists()
                                    or bunch_out.stat().st_size == 0))
        del df, bunch_df

        for k in total:
            total[k] += counts[k]
        print(f"    done in {time.monotonic() - start:.1f}s "
              f"({counts['packets']} packets, {counts['bunches']} bunches; "
              f"{total['packets']} packets total so far)", flush=True)

    print(f"\nProcessed {len(files)} pcap file(s): "
          f"{total['packets']} packet(s), {total['bunches']} bunch(es) "
          f"in {time.monotonic() - total_start:.1f}s.")
    print(f"Wrote {out}")
    if total["bunches"]:
        print(f"Wrote {bunch_out}")
    print(f"Handshake packets: {total['handshake']}, data packets: {total['data']}, "
          f"with parse errors: {total['errors']}")


if __name__ == "__main__":
    main()
