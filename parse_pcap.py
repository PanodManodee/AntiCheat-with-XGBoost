#!/usr/bin/env python3
"""Map pcap packet fields onto the .bin-derived ground-truth CSV.

For each input pcap:
  1. decode the UDP payloads with ``PcapAdaptor`` (pcap_adaptor.py), reusing the
     UE5 network implementation (FBitReader / StatelessConnect / packet + bunch
     headers);
  2. auto-locate the matching ground truth in ``parsed_all_packets.csv`` from the
     pcap path (``capture_server_<ts>.pcap`` -> ``trace_server_<ts>.bin``,
     resolved within the same session/match directory);
  3. join every wire packet to its ground-truth row by seq, acked_seq or nearest
     timestamp (within a configurable window);
  4. write one merged packet CSV + a lean bunch CSV + an event-label CSV.

Field pairs that exist on both sides are kept under explicit prefixes
(``wire_*`` for the pcap decoder, ``bin_*`` for the ground truth) so they can be
cross-checked without column-name collisions; genuinely duplicated columns
(payload hex, raw coordinates blocks, ``header.ids.hash_data`` vs ``hash_data``,
bin ``timestamp`` vs ``ts``, etc.) are dropped from the output.

Ground truth is streamed in chunks and only rows belonging to the needed bins are
retained, so peak memory stays proportional to the matched subset rather than the
full 1.9 GB CSV.

Usage:
    parse_pcap.py <pcap file(s)|directory|glob> [--output FILE]
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import IP, UDP

import pcap_adaptor
from pcap_adaptor import PcapAdaptor, discover_files

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_TRUTH = BASE_DIR / "parsed_all_packets.csv"
DEFAULT_OUTPUT = "pcap_mapped.csv"
DEFAULT_SERVER_PORT = 7777

# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------

# Ground-truth columns we actually need. Every name here exists in
# parsed_all_packets.csv (the flattened .bin). They are renamed to ``bin_*``.
TRUTH_READ_COLS = [
    "file", "session", "match", "ts", "ind", "frame", "outgoing", "incoming",
    "hash_data", "entry_type", "event_type",
    "header.ids.sessionid", "header.ids.clientid", "header.ids.ipaddress",
    "notification.type", "notification.seq", "notification.acked_seq",
    "notification.extra_info_header.type",
    "notification.extra_info_header.jitter_clock",
    "phase_event.phase_name", "phase_event.start",
    "health.player_id", "health.old", "health.new_",
    "movement.player_id", "movement.dS", "movement.ts_client",
    "movement.new_location", "movement.new_rotation",
    "weapon.player_id", "weapon.ot", "weapon.time", "weapon.dist",
    "weapon.target_id", "weapon.bone", "weapon.blind", "weapon.weapon",
    "weapon.visible_players", "weapon.cartridge_id",
    "cheat.cheater_id", "cheat.target_id", "cheat.type", "cheat.start",
    "cheat.dur", "cheat.out", "cheat.in_",
    "header.handshake.packet_type", "header.handshake.sent_packet_count",
    "header.handshake.restart", "header.handshake.secretid",
    "header.handshake.ts", "header.handshake.cookie",
]
TRUTH_RENAME = {
    "file": "bin_file", "ts": "bin_ts", "ind": "bin_ind", "frame": "bin_frame",
    "outgoing": "bin_outgoing", "incoming": "bin_incoming",
    "hash_data": "bin_hash_data",
    "entry_type": "bin_entry_type", "event_type": "bin_event_type",
    "session": "bin_session", "match": "bin_match",
    "header.ids.sessionid": "bin_sessionid",
    "header.ids.clientid": "bin_clientid",
    "header.ids.ipaddress": "bin_ipaddress",
    "notification.type": "bin_notif_type",
    "notification.seq": "bin_notif_seq",
    "notification.acked_seq": "bin_notif_acked_seq",
    "notification.extra_info_header.type": "bin_extra_info_type",
    "notification.extra_info_header.jitter_clock": "bin_jitter_clock",
    "phase_event.phase_name": "bin_phase_name",
    "phase_event.start": "bin_phase_start",
    "health.player_id": "bin_health_player_id",
    "health.old": "bin_health_old",
    "health.new_": "bin_health_new",
    "movement.player_id": "bin_movement_player_id",
    "movement.dS": "bin_movement_dS",
    "movement.ts_client": "bin_movement_ts_client",
    "movement.new_location": "bin_movement_loc",
    "movement.new_rotation": "bin_movement_rot",
    "weapon.player_id": "bin_weapon_player_id",
    "weapon.ot": "bin_weapon_ot",
    "weapon.time": "bin_weapon_time",
    "weapon.dist": "bin_weapon_dist",
    "weapon.target_id": "bin_weapon_target_id",
    "weapon.bone": "bin_weapon_bone",
    "weapon.blind": "bin_weapon_blind",
    "weapon.weapon": "bin_weapon_weapon",
    "weapon.visible_players": "bin_weapon_visible_players",
    "weapon.cartridge_id": "bin_weapon_cartridge_id",
    "cheat.cheater_id": "bin_cheat_cheater_id",
    "cheat.target_id": "bin_cheat_target_id",
    "cheat.type": "bin_cheat_type",
    "cheat.start": "bin_cheat_start",
    "cheat.dur": "bin_cheat_dur",
    "cheat.out": "bin_cheat_out",
    "cheat.in_": "bin_cheat_in",
    "header.handshake.packet_type": "bin_handshake_packet_type",
    "header.handshake.sent_packet_count": "bin_handshake_sent_packet_count",
    "header.handshake.restart": "bin_handshake_restart",
    "header.handshake.secretid": "bin_handshake_secretid",
    "header.handshake.ts": "bin_handshake_ts",
    "header.handshake.cookie": "bin_handshake_cookie",
}
TRUTH_OUT_COLS = list(TRUTH_RENAME.values())

# Wire ("adaptor") columns exposed in the merged output, renamed ``wire_*`` so
# they never collide with the ground-truth columns.
WIRE_DEF = {
    "file": "file",                 # pcap basename
    "packet_no": "packet_no",
    "timestamp": "timestamp",
    "flow": "flow",
    "client_ip": "client_ip",
    "client_port": "client_port",
    "payload_len": "payload_len",
    "is_handshake": "wire_is_handshake",
    "packet_type": "wire_packet_type",
    "network_version": "wire_network_version",
    "min_version": "wire_min_version",
    "handshake_version": "wire_handshake_version",
    "restarted": "wire_restarted",
    "runtime_features": "wire_runtime_features",
    "secret_id": "wire_secret_id",
    "timestamp_f": "wire_timestamp_f",
    "cookie_hex": "wire_cookie_hex",
    "client_id": "wire_client_id",
    "travel_count": "wire_travel_count",
    "cached_client_id": "wire_cached_client_id",
    "seq": "wire_seq",
    "acked_seq": "wire_acked_seq",
    "has_packet_info": "wire_has_packet_info",
    "jitter_clock_ms": "wire_jitter_ms",
    "has_server_frame_time": "wire_has_server_frame_time",
    "server_frame_time": "wire_server_frame_ms",
    "channels": "wire_channels",
    "bunch_count": "wire_bunch_count",
    "error": "wire_error",
    "bunch_parse_error": "wire_bunch_parse_error",
    "short_packet": "wire_short_packet",
}
WIRE_OUT_COLS = list(WIRE_DEF.values())

PACKET_OUT_COLS = WIRE_OUT_COLS + TRUTH_OUT_COLS + [
    "join_method", "join_delta_ms",
]

# Lean bunch-level output: parent packet context + join meta + wire bunch fields
# (the flags/sequence per channel that the flat packet rows cannot carry).
BUNCH_PKT_COLS = [
    "file", "packet_no", "timestamp", "flow", "client_ip", "client_port",
    "payload_len", "wire_seq", "wire_acked_seq", "wire_is_handshake",
    "wire_channels", "wire_bunch_parse_error",
    "join_method", "join_delta_ms",
    "bin_file", "bin_ts", "bin_outgoing", "bin_incoming", "bin_entry_type",
    "bin_event_type", "bin_notif_seq",
]
BUNCH_FIELD_COLS = [
    "bunch_no", "ch_index", "ch_name", "reliable", "open", "close", "partial",
    "partial_initial", "partial_final", "ch_sequence",
    "has_package_map_exports", "has_must_be_mapped_guids", "payload_bits",
]
BUNCH_OUT_COLS = BUNCH_PKT_COLS + BUNCH_FIELD_COLS

BUNCH_RENAME = {
    "seq": "wire_seq", "acked_seq": "wire_acked_seq",
    "is_handshake": "wire_is_handshake", "channels": "wire_channels",
    "bunch_parse_error": "wire_bunch_parse_error",
}

# Ground-truth event rows (movement/weapon/health/cheat/phase) are stored as
# separate entries with their own timestamp. They are emitted to a companion
# *_events.csv so the cheat/weapon/movement labels can be joined to packets by
# time (event.ts ~ packet.bin_ts).
EVENT_OUT_COLS = [
    "bin_file", "bin_ts", "bin_ind", "bin_frame", "bin_entry_type", "bin_event_type",
    "bin_sessionid", "bin_clientid",
    "bin_phase_name", "bin_phase_start",
    "bin_health_player_id", "bin_health_old", "bin_health_new",
    "bin_movement_player_id", "bin_movement_dS", "bin_movement_ts_client",
    "bin_movement_loc", "bin_movement_rot",
    "bin_weapon_player_id", "bin_weapon_ot", "bin_weapon_time", "bin_weapon_dist",
    "bin_weapon_target_id", "bin_weapon_bone", "bin_weapon_blind", "bin_weapon_weapon",
    "bin_weapon_visible_players", "bin_weapon_cartridge_id",
    "bin_cheat_cheater_id", "bin_cheat_target_id", "bin_cheat_type", "bin_cheat_start",
    "bin_cheat_dur", "bin_cheat_out", "bin_cheat_in",
]


def _canonicalize(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Reindex to a fixed column order and blank out any missing cells."""
    df = df.copy()
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    return df[columns].astype(object).fillna("")


# ----------------------------------------------------------------------------
# Ground-truth loading (memory-safe, chunked)
# ----------------------------------------------------------------------------

def bin_key_from_pcap(pcap_path: Path) -> str | None:
    """capture_server_<ts>.pcap -> trace_server_<ts>.bin (or None if no match)."""
    m = re.match(r"^capture_(.+\.pcap(?:ng)?)$", pcap_path.name, re.IGNORECASE)
    if not m:
        return None
    stem = re.sub(r"\.pcap(?:ng)?$", ".bin", m.group(1), flags=re.IGNORECASE)
    return "trace_" + stem


def _norm_name(name: str) -> str:
    """Normalise a bin/trace filename to compare timestamps regardless of
    -, _ or 'merged' suffixes (e.g. trace_server_2026.02.20_15.36.45_merged.bin)."""
    return re.sub(r"[^0-9:.]", "", name)


def index_truth(truth_path: Path) -> tuple[pd.DataFrame, list[str]]:
    """One-column pass listing distinct (file, session, match) values cheaply.

    Returns (DataFrame, run_order) where run_order is the first-appearance
    (contiguous-run) order of the bin files in the CSV.
    """
    seen: dict[str, tuple[str, str]] = {}
    order: list[str] = []
    t0 = time.monotonic()
    for i, chunk in enumerate(
        pd.read_csv(truth_path, usecols=["file", "session", "match"], chunksize=500_000)
    ):
        for f, s, m in zip(chunk["file"], chunk["session"], chunk["match"]):
            if f not in seen:
                seen[f] = (s, m)
                order.append(f)
        if i and i % 10 == 0:
            print(f"  index pass chunk {i*500_000:,} rows in {time.monotonic()-t0:.0f}s", flush=True)
    idx = pd.DataFrame(
        [{"file": f, "session": s, "match": m} for f, (s, m) in seen.items()]
    )
    print(f"  index pass done: {len(idx)} distinct bins in {time.monotonic()-t0:.0f}s")
    return idx, order


def resolve_truth_files(pcaps: list[Path], index: pd.DataFrame) -> dict[str, str]:
    """Map each pcap to the best ground-truth 'file' value (exact name, else
    timestamp-normalised match constrained to the same session/match)."""
    resolution: dict[str, str] = {}
    by_norm = index.copy()
    by_norm["_norm"] = by_norm["file"].map(_norm_name)
    for pcap in pcaps:
        key = bin_key_from_pcap(pcap)
        if key is None:
            continue
        if key in set(index["file"]):
            resolution[str(pcap)] = key
            continue
        session = pcap.parts[-3] if len(pcap.parts) >= 3 else None
        match = pcap.parts[-2] if len(pcap.parts) >= 2 else None
        sub = by_norm
        if session is not None:
            sub = sub[sub["session"] == session]
        if match is not None:
            sub = sub[sub["match"] == match]
        hits = sub[sub["_norm"] == _norm_name(key)]
        if hits.empty:
            hits = sub[sub["_norm"].str.startswith(_norm_name(key).replace(".", ""), na=False)]
        if not hits.empty:
            resolution[str(pcap)] = str(hits.sort_values("file").iloc[0]["file"])
    return resolution


def iter_truth_runs(truth_path: Path, needed_files: set[str]):
    """Stream parsed_all_packets.csv run-by-run (rows are grouped by 'file').

    Yields ``(bin_file, DataFrame)`` for each *needed* contiguous run, so peak
    memory stays proportional to the largest single bin rather than the union
    of all needed bins.
    """
    t0 = time.monotonic()
    cur_file: str | None = None
    cur: list[pd.DataFrame] = []
    # NOTE: pandas 3.0.3 crashes with `usecols` + `chunksize` on wide tables
    # (IndexError in c_parser_wrapper). Read the full chunk and slice the needed
    # columns after selecting the current run. Default dtypes keep numeric
    # columns as numpy arrays (lighter than per-cell strings).
    for i, chunk in enumerate(
        pd.read_csv(
            truth_path, low_memory=False, keep_default_na=True, chunksize=200_000
        )
    ):
        if i and i % 50 == 0:
            print(f"  truth pass {i*200_000:,} rows in {time.monotonic()-t0:.0f}s",
                  flush=True)
        vals = chunk["file"].to_numpy()
        if vals.size == 0:
            continue
        change = np.flatnonzero(vals[1:] != vals[:-1]) + 1
        bounds = np.concatenate(([0], change, [vals.size]))
        for s, e in zip(bounds[:-1], bounds[1:]):
            f = vals[s]
            sub = chunk.iloc[s:e][TRUTH_READ_COLS]
            if f == cur_file:
                if cur_file in needed_files:
                    cur.append(sub)
                continue
            if cur_file in needed_files and cur:
                yield cur_file, _finish_run(pd.concat(cur, ignore_index=True))
            cur_file = f
            cur = [sub] if f in needed_files else []
    if cur_file in needed_files and cur:
        yield cur_file, _finish_run(pd.concat(cur, ignore_index=True))
    print(f"  truth pass done in {time.monotonic()-t0:.0f}s", flush=True)


def _finish_run(df: pd.DataFrame) -> pd.DataFrame:
    """Rename/derive the standard truth columns for one bin's DataFrame."""
    df = df.rename(columns=TRUTH_RENAME)
    for c in ("bin_notif_seq", "bin_notif_acked_seq", "bin_jitter_clock"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    if "bin_ts" in df.columns:
        ts = pd.to_datetime(df["bin_ts"], utc=True, errors="coerce")
        df["_bin_ts_epoch"] = _to_epoch_sec(ts)
    else:
        df["_bin_ts_epoch"] = np.nan
    return df


# ----------------------------------------------------------------------------
# Join
# ----------------------------------------------------------------------------

def _coerce_float(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce")


def _as_bool(s: pd.Series) -> pd.Series:
    """Coerce truth flags ('True'/'True'/1/1.0/NaN) into nullable booleans."""
    num = pd.to_numeric(s, errors="coerce")
    as_num = num.notna()
    as_str = s.astype(str).str.strip().str.lower().eq("true").where(~as_num, False)
    return (num.fillna(0).astype("float64") > 0) | as_str


def _to_epoch_sec(ts: pd.Series) -> np.ndarray:
    """UTC datetime Series -> float seconds since epoch (NaN for NaT)."""
    ts = ts.copy()
    if ts.dt.tz is None:
        ts = ts.dt.tz_localize("UTC")
    return (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy(dtype="float64")


def join_truth(
    wire: pd.DataFrame, truth: pd.DataFrame, window_s: float
) -> pd.DataFrame:
    """Join wire packet rows onto ground-truth rows.

    Priority: exact notification.seq -> exact acked_seq -> nearest timestamp
    within ``window_s``. Handshake packets are matched by timestamp only.
    Truth position 0..len(truth)-1 is the global position used for selection.
    """
    wire = wire.copy()
    for c in ("wire_seq", "wire_acked_seq", "timestamp"):
        if c in wire.columns:
            wire[c] = _coerce_float(wire[c])

    pointers: list[tuple[int, int, str, float]] = []  # (pos, truth_pos, method, delta_ms)
    used: set[int] = set()

    if "bin_handshake_packet_type" in truth.columns:
        hsfull = truth[truth["bin_handshake_packet_type"].notna()]
    else:
        hsfull = truth.iloc[0:0]
    hs_epoch = hsfull["_bin_ts_epoch"].to_numpy(dtype="float64")
    hs_pos = hsfull.index.to_numpy(dtype="int64")

    for axis in ("cs", "sc"):
        wm = wire["flow"].fillna("") == axis
        positions = wire.index[wm].to_numpy(dtype="int64")
        if not positions.size:
            continue
        dir_col = "bin_incoming" if axis == "cs" else "bin_outgoing"
        t = truth[_as_bool(truth[dir_col])]

        if t.empty:
            pointers.extend((int(p), -1, "unmatched", np.nan) for p in positions)
            continue

        seq_map: dict[int, list[int]] = {}
        for s, gi in zip(
            t["bin_notif_seq"].to_numpy(dtype="float64"), t.index.to_numpy(dtype="int64")
        ):
            if not pd.isna(s):
                seq_map.setdefault(int(s), []).append(int(gi))
        epoch = t["_bin_ts_epoch"].to_numpy(dtype="float64")
        t_gpos = t.index.to_numpy(dtype="int64")

        pos_to_slot = {int(g): int(i) for i, g in enumerate(t_gpos)}
        epoch_by_g = {g: epoch[pos_to_slot[g]] for g in t_gpos}

        def in_window(cands: list[int], wts: float) -> list[tuple[int, float]]:
            return [
                (g, abs(epoch_by_g[g] - wts) * 1000.0)
                for g in cands
                if g not in used and abs(epoch_by_g[g] - wts) <= window_s
            ]

        for pos in positions:
            row = wire.loc[pos]
            wseq = row.get("wire_seq")
            wack = row.get("wire_acked_seq")
            wts = row.get("timestamp")

            if pd.isna(wts):
                pointers.append((int(pos), -1, "unmatched", np.nan))
                continue

            best: tuple[int, str, float] | None = None
            if not pd.isna(wseq):
                cands = in_window(seq_map.get(int(wseq), []), float(wts))
                if cands:
                    g, dms = min(cands, key=lambda x: x[1])
                    best = (g, "seq", dms)
            if best is None and not pd.isna(wack):
                cands = in_window(seq_map.get(int(wack), []), float(wts))
                if cands:
                    g, dms = min(cands, key=lambda x: x[1])
                    best = (g, "acked_seq", dms)
            if best is None:
                dt = np.abs(epoch - float(wts))
                j = int(np.argmin(dt))
                g = int(t_gpos[j])
                if dt[j] <= window_s and g not in used:
                    best = (g, "time", float(dt[j]) * 1000.0)

            if best is not None:
                g, method, dms = best
                used.add(g)
                pointers.append((int(pos), g, method, dms))
            else:
                pointers.append((int(pos), -1, "unmatched", np.nan))

    # Handshake-only packets (no seq yet) -> nearest handshake row in time.
    hsmask = wire["wire_is_handshake"].fillna(False).astype(bool)
    handled = {p[0] for p in pointers}
    for pos in wire.index[hsmask].to_numpy(dtype="int64"):
        if pos in handled:
            continue
        wts = wire.at[pos, "timestamp"]
        if hs_epoch.size == 0 or pd.isna(wts):
            pointers.append((int(pos), -1, "unmatched", np.nan))
            continue
        dt = np.abs(hs_epoch - float(wts))
        j = int(np.argmin(dt))
        if dt[j] <= window_s:
            pointers.append((int(pos), int(hs_pos[j]), "time", float(dt[j]) * 1000.0))
        else:
            pointers.append((int(pos), -1, "unmatched", np.nan))

    # Any wire row with no pointer (e.g. dropped frames) -> unmatched.
    have = {p[0] for p in pointers}
    for pos in wire.index.to_numpy(dtype="int64"):
        if pos not in have:
            pointers.append((int(pos), -1, "unmatched", np.nan))

    pf = pd.DataFrame(
        pointers, columns=["pos", "truth_pos", "method", "delta_ms"]
    ).sort_values("pos").drop_duplicates(subset="pos", keep="first")

    pad = pd.DataFrame([[np.nan] * len(truth.columns)], columns=truth.columns)
    tball = pd.concat([truth, pad], ignore_index=True)
    pad_pos = len(truth)
    sel = np.where(pf["truth_pos"].values < 0, pad_pos, pf["truth_pos"].values)

    wire_sel = wire.iloc[pf["pos"].to_numpy(dtype="int64")].reset_index(drop=True)
    truth_sel = tball.iloc[sel].reset_index(drop=True)
    truth_sel = truth_sel.drop(columns=["_bin_ts_epoch"], errors="ignore")

    merged = pd.concat([wire_sel, truth_sel], axis=1)
    merged["join_method"] = pf["method"].values
    merged["join_delta_ms"] = pf["delta_ms"].values
    return merged


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        description="Map pcap packet fields onto the .bin-derived ground-truth CSV."
    )
    p.add_argument("inputs", nargs="+",
                   help="pcap file(s), directories (recursively scanned) or glob patterns")
    p.add_argument("--output", default=DEFAULT_OUTPUT,
                   help="output packet CSV (default: %(default)s)")
    p.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT,
                   help="UDP server port identifying the flows (default: %(default)s)")
    p.add_argument("--truth", default=str(DEFAULT_TRUTH),
                   help="ground-truth CSV (default: %(default)s)")
    p.add_argument("--match-window-ms", type=float, default=50.0,
                   help="time-window used for the fallback join (default: %(default)s)")
    p.add_argument("--no-bunches", action="store_true",
                   help="skip the bunch-level output CSV")
    p.add_argument("--no-events", action="store_true",
                   help="skip the event-label output CSV")
    a = p.parse_args(argv)

    truth_path = Path(a.truth)
    if not truth_path.exists():
        print(f"Ground truth not found: {truth_path}")
        return 1

    pcaps = discover_files(a.inputs)
    if not pcaps:
        print(f"No .pcap files found under {a.inputs}")
        return 1
    print(f"Found {len(pcaps)} pcap file(s)")

    # --- locate ground-truth rows ----------------------------------------
    print("Indexing ground truth...", flush=True)
    index, run_order = index_truth(truth_path)
    resolution = resolve_truth_files(pcaps, index)
    needed = {f for f in resolution.values()}
    print(f"resolved {len(needed)} ground-truth bin(s): {sorted(needed)}")

    # --- process pcaps, streaming ground truth run-by-run ------------------
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    bunch_out = out.with_name(out.stem + "_bunches.csv")
    events_out = out.with_name(out.stem + "_events.csv")
    for path in (out, bunch_out, events_out):
        path.unlink(missing_ok=True)

    adaptor = PcapAdaptor(server_port=a.server_port)
    totals = {"packets": 0, "bunches": 0, "events": 0, "handshake": 0, "data": 0, "errors": 0}
    methods_total = {"seq": 0, "acked_seq": 0, "time": 0, "unmatched": 0, "no_truth": 0}
    events_written: set[str] = set()

    run_pos = {f: i for i, f in enumerate(run_order)}
    pcaps_ordered = sorted(
        pcaps, key=lambda p: run_pos.get(resolution.get(str(p), ""), 10**9)
    )
    n = 0
    start_all = time.monotonic()

    def run_one(pcap: Path, text_file: str | None,
                truth: pd.DataFrame | None) -> None:
        nonlocal n
        n += 1
        pcap_s = str(pcap)
        print(f"[{n}/{len(pcaps)}] {pcap_s} -> truth '{text_file or 'NONE'}'", flush=True)
        t0 = time.monotonic()
        df, bunch_df, counts = adaptor.process_file(pcap)

        wire = df[list(WIRE_DEF)].rename(columns=WIRE_DEF)
        merged = (
            join_truth(wire, truth, a.match_window_ms / 1000.0)
            if truth is not None else _no_truth_frame(wire)
        )
        merged = _canonicalize(merged, PACKET_OUT_COLS)

        for m in ("seq", "acked_seq", "time", "unmatched", "no_truth"):
            methods_total[m] += int((merged["join_method"] == m).sum())

        merged.to_csv(out, mode="a", index=False,
                      header=(n == 1 or out.stat().st_size == 0))

        bunch_written = False
        if not a.no_bunches and bunch_df is not None and not bunch_df.empty:
            b = _build_bunches(bunch_df, merged)
            if not b.empty:
                b.to_csv(bunch_out, mode="a", index=False,
                         header=(not bunch_out.exists() or bunch_out.stat().st_size == 0))
                bunch_written = True

        events_written_flag = False
        if (
            not a.no_events
            and truth is not None
            and text_file not in events_written
        ):
            ev = extract_events(truth)
            if not ev.empty:
                ev.to_csv(events_out, mode="a", index=False,
                          header=(not events_out.exists() or events_out.stat().st_size == 0))
                totals["events"] += len(ev)
                events_written.add(text_file)
                events_written_flag = True

        for k in counts:
            totals[k] += counts[k]
        dt = time.monotonic() - t0
        print(f"    {counts['packets']:,} packets, {counts['bunches']:,} bunches "
              f"({dt:.1f}s); bunches-csv:{'yes' if bunch_written else 'no'}"
              f" events-csv:{'yes' if events_written_flag else 'no'}", flush=True)
        del df, merged
        if "bunch_df" in locals():
            del bunch_df

    delivered: set[str] = set()
    if needed:
        print("Streaming ground-truth runs...", flush=True)
        for f, truth in iter_truth_runs(truth_path, needed):
            delivered.add(f)
            for pcap in (p for p in pcaps_ordered if resolution.get(str(p)) == f):
                run_one(pcap, f, truth)
            del truth

    for pcap in pcaps_ordered:
        f = resolution.get(str(pcap))
        if f is None or f not in delivered:
            run_one(pcap, None, None)

    print(f"\nProcessed {len(pcaps)} pcap(s): {totals['packets']:,} packets, "
          f"{totals['bunches']:,} bunches, {totals['errors']:,} errors "
          f"in {time.monotonic()-start_all:.0f}s")
    print("Join methods:", methods_total)
    print(f"Wrote {out}")
    if not a.no_bunches and bunch_out.exists():
        print(f"Wrote {bunch_out}")
    if not a.no_events and events_out.exists():
        print(f"Wrote {events_out} ({totals['events']:,} event rows)")
    return 0


def _no_truth_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Wire rows with no ground truth: blank truth fields + no_truth method."""
    out = df.copy()
    out["join_method"] = "no_truth"
    out["join_delta_ms"] = np.nan
    return out


def extract_events(truth: pd.DataFrame) -> pd.DataFrame:
    """Event-type ground-truth rows (movement/weapon/health/cheat/phase)."""
    if "bin_entry_type" not in truth.columns:
        return pd.DataFrame()
    ev = truth[truth["bin_entry_type"].astype(str) == "event"]
    if ev.empty:
        return ev
    return _canonicalize(ev, EVENT_OUT_COLS)


def _build_bunches(bunch_df: pd.DataFrame, merged: pd.DataFrame) -> pd.DataFrame:
    """Attach each wire bunch to its parent packet's join context."""
    bunch = bunch_df.copy()
    bunch = bunch.rename(columns={k: v for k, v in BUNCH_RENAME.items() if k in bunch.columns})
    keep_pkt = [c for c in BUNCH_PKT_COLS if c in merged.columns]
    ctx = merged[keep_pkt].drop_duplicates(subset=["file", "packet_no"])
    for target in (bunch, ctx):
        target["packet_no"] = pd.to_numeric(target["packet_no"], errors="coerce").astype("Int64")
    merged_local = bunch.merge(ctx, on=["file", "packet_no"], how="left", suffixes=("", "_y"))
    for c in BUNCH_PKT_COLS:
        if c + "_y" in merged_local.columns:
            merged_local[c] = merged_local[c + "_y"].fillna(merged_local[c])
            merged_local = merged_local.drop(columns=[c + "_y"])
    for c in BUNCH_FIELD_COLS:
        if c in bunch.columns and c not in merged_local.columns:
            merged_local[c] = bunch[c]
    return _canonicalize(merged_local, BUNCH_OUT_COLS)


if __name__ == "__main__":
    sys.exit(main())