#!/usr/bin/env python3
"""Map pcap packet fields onto the server ground truth shipped in the dataset.

For each input pcap (``dataset/<Session>/<Match>/Server/capture_server_<ts>.pcap``):

  1. decode the UDP payloads with ``PcapAdaptor`` (pcap_adaptor.py), reusing
     the UE5 network implementation (handler prefix, packet header, packet
     info, bunch headers);
  2. load the sibling ground truth ``trace_server_<ts>.bin`` (or ``.csv``)
     with ``truth_loader`` - no global CSV needed;
  3. resolve every client ``ip:port`` to the truth address id and player id
     (``new_address`` / ``new_player`` events);
  4. join each wire packet to its truth packet row by (client, direction, seq),
     falling back to the nearest unused row of the same client/direction in
     time;
  5. label each packet with the cheats its player is running (and cheats
     aimed at that player) from the start/stop cheat events;
  6. write ``<out>.csv`` (packets), ``<out>_bunches.csv`` (wire bunches) and
     ``<out>_events.csv`` (truth events with resolved actor + cheat label).

Column prefixes: ``wire_*`` comes from the pcap decoder, ``bin_*`` from the
ground truth. Note on ``acked_seq``: for server->client packets
``wire_acked_seq`` is the header's AckedSeq (the last *client* seq the server
received); the truth's ``bin_notif_acked_seq`` on outgoing rows is the
server's own last-acked out-seq, so the two legitimately differ on ``sc``.

Usage:
    parse_pcap.py <pcap file(s)|directory|glob> [--output FILE]
                  [--truth-source auto|bin|csv] [--truth TRACE]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from pcap_adaptor import PcapAdaptor, discover_files
from truth_loader import BUNCH_FEATURE_COLS, find_truth, load_truth

DEFAULT_OUTPUT = "pcap_mapped.csv"
DEFAULT_SERVER_PORT = 7777

# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------

# Wire ("adaptor") columns exposed in the merged output.
WIRE_DEF = {
    "file": "file",                 # pcap basename
    "packet_no": "packet_no",
    "timestamp": "timestamp",
    "flow": "flow",
    "client_ip": "client_ip",
    "client_port": "client_port",
    "packet_length": "packet_length",
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
    "history_word_count": "wire_history_word_count",
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

# Truth packet-row columns (dotted truth name -> output name).
PKT_TRUTH_RENAME = {
    "file": "bin_file", "session": "bin_session", "match": "bin_match",
    "ts": "bin_ts", "ind": "bin_ind", "frame": "bin_frame",
    "outgoing": "bin_outgoing", "incoming": "bin_incoming",
    "hash_data": "bin_hash_data",
    "header.ids.sessionid": "bin_sessionid",
    "header.ids.clientid": "bin_clientid",
    "header.ids.ipaddress": "bin_ipaddress",
    "notification.type": "bin_notif_type",
    "notification.seq": "bin_notif_seq",
    "notification.acked_seq": "bin_notif_acked_seq",
    "_addr": "bin_client_addr",
    "notification.extra_info_header.type": "bin_extra_info_type",
    "notification.extra_info_header.jitter_clock": "bin_jitter_clock",
    **{c: c for c in BUNCH_FEATURE_COLS},
}
PKT_TRUTH_OUT_COLS = list(PKT_TRUTH_RENAME.values())

IDENTITY_COLS = ["client_addr", "address_id", "player_id", "player_name",
                 "player_map_method"]
LABEL_COLS = ["cheat_active", "cheat_types", "cheat_target_active",
              "cheat_target_types"]

PACKET_OUT_COLS = (
    WIRE_OUT_COLS + IDENTITY_COLS + LABEL_COLS + PKT_TRUTH_OUT_COLS
    + ["wire_bin_bunch_count_diff", "join_method", "join_delta_ms"]
)

# Bunch-level output: parent packet context + wire bunch fields.
BUNCH_PKT_COLS = [
    "file", "packet_no", "timestamp", "flow", "client_ip", "client_port",
    "client_addr", "player_id", "cheat_active", "cheat_types",
    "payload_len", "wire_seq", "wire_acked_seq", "wire_is_handshake",
    "wire_channels", "wire_bunch_parse_error",
    "join_method", "join_delta_ms", "bin_file", "bin_ts", "bin_notif_seq",
]
BUNCH_FIELD_COLS = [
    "bunch_no", "ch_index", "ch_name", "reliable", "open", "close",
    "close_reason", "is_replication_paused", "partial", "partial_initial",
    "partial_final", "partial_custom_exports_final", "ch_sequence",
    "has_package_map_exports", "has_must_be_mapped_guids", "payload_bits",
]
BUNCH_OUT_COLS = BUNCH_PKT_COLS + BUNCH_FIELD_COLS
BUNCH_RENAME = {
    "seq": "wire_seq", "acked_seq": "wire_acked_seq",
    "is_handshake": "wire_is_handshake", "channels": "wire_channels",
    "bunch_parse_error": "wire_bunch_parse_error",
}

# Truth event columns (dotted -> output). List-valued fields are expanded in
# ``extract_events``.
EVENT_RENAME = {
    "file": "bin_file", "session": "bin_session", "match": "bin_match",
    "ts": "bin_ts", "ind": "bin_ind", "frame": "bin_frame",
    "event_type": "bin_event_type",
    "new_address.address_id": "bin_new_address_id",
    "new_address.ip": "bin_new_address_ip",
    "new_player.player_id": "bin_new_player_id",
    "new_player.name": "bin_new_player_name",
    "new_player.ip_port": "bin_new_player_ip_port",
    "new_player.update_ip_port": "bin_new_player_update_ip_port",
    "phase_event.phase_name": "bin_phase_name",
    "phase_event.start": "bin_phase_start",
    "health.player_id": "bin_health_player_id",
    "health.old": "bin_health_old",
    "health.new_": "bin_health_new",
    "movement.player_id": "bin_movement_player_id",
    "movement.dS": "bin_movement_dS",
    "movement.ts_client": "bin_movement_ts_client",
    "weapon.player_id": "bin_weapon_player_id",
    "weapon.ot": "bin_weapon_ot",
    "weapon.time": "bin_weapon_time",
    "weapon.dist": "bin_weapon_dist",
    "weapon.target_id": "bin_weapon_target_id",
    "weapon.bone": "bin_weapon_bone",
    "weapon.blind": "bin_weapon_blind",
    "weapon.weapon": "bin_weapon_weapon",
    "weapon.cartridge_id": "bin_weapon_cartridge_id",
    "cheat.cheater_id": "bin_cheat_cheater_id",
    "cheat.target_id": "bin_cheat_target_id",
    "cheat.type": "bin_cheat_type",
    "cheat.start": "bin_cheat_start",
    "cheat.dur": "bin_cheat_dur",
    "cheat.out": "bin_cheat_out",
    "cheat.in_": "bin_cheat_in",
}
EVENT_OUT_COLS = (
    list(EVENT_RENAME.values())
    + ["bin_movement_loc_x", "bin_movement_loc_y", "bin_movement_loc_z",
       "bin_movement_rot", "bin_weapon_visible_players",
       "bin_weapon_visible_count",
       "actor_player_id", "actor_name", "actor_addr"]
    + LABEL_COLS
)

# Player-id columns per event type (first non-null wins).
ACTOR_COLS = ["health.player_id", "movement.player_id", "weapon.player_id",
              "cheat.cheater_id", "new_player.player_id"]


def _canonicalize(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Reindex to a fixed column order and blank out any missing cells."""
    df = df.copy()
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    return df[columns].astype(object).fillna("")


def _col(df: pd.DataFrame, name: str) -> pd.Series:
    return df[name] if name in df.columns else pd.Series(np.nan, index=df.index)


def _truthy(s: pd.Series) -> np.ndarray:
    """True for True / 'True' / 1; False for False / NaN / ''."""
    return s.map(lambda v: v is True or v == 1 or str(v).strip().lower() == "true"
                 ).to_numpy(dtype=bool)


# ----------------------------------------------------------------------------
# Identity: ip:port <-> address id <-> player id
# ----------------------------------------------------------------------------

class Identity:
    """Client identity resolved from the truth ``new_address``/``new_player``
    events. Player registrations are time-aware: the latest registration of
    an ``ip:port`` at (or, if none yet, after) a given time wins."""

    def __init__(self, truth: pd.DataFrame):
        ev = truth[truth["entry_type"] == "event"]
        na = ev[ev["event_type"] == "new_address"]
        self.addr_by_id: dict[int, str] = {}
        for a, ip in zip(_col(na, "new_address.address_id"), _col(na, "new_address.ip")):
            if pd.notna(a) and isinstance(ip, str) and ip:
                self.addr_by_id[int(a)] = ip
        self.id_by_addr = {ip: a for a, ip in self.addr_by_id.items()}

        npl = ev[ev["event_type"] == "new_player"]
        reg = pd.DataFrame({
            "t": npl["_ts_epoch"].to_numpy(dtype="float64"),
            "pid": pd.to_numeric(_col(npl, "new_player.player_id"), errors="coerce"),
            "name": _col(npl, "new_player.name"),
            "addr": _col(npl, "new_player.ip_port"),
        }).dropna(subset=["pid"]).sort_values("t", kind="stable")
        self.names = {int(p): n for p, n in zip(reg["pid"], reg["name"])
                      if isinstance(n, str) and n}
        self.reg = reg[reg["addr"].map(lambda a: isinstance(a, str) and ":" in a)]
        self.reg = self.reg.assign(ip=self.reg["addr"].str.rsplit(":", n=1).str[0])

    def truth_addr(self, tp: pd.DataFrame) -> pd.Series:
        """Client ip:port of truth packet rows."""
        by_id = pd.to_numeric(_col(tp, "header.ids.ipaddress"), errors="coerce").map(
            lambda a: self.addr_by_id.get(int(a)) if pd.notna(a) else np.nan)
        direct = _col(tp, "notification.address")
        return direct.where(direct.notna(), by_id)

    def players_for(self, addrs: np.ndarray, t: np.ndarray):
        """Resolve (addr, time) arrays -> (player_id float array, method array)."""
        pid = np.full(len(addrs), np.nan)
        method = np.full(len(addrs), "none", dtype=object)
        for addr in pd.unique(addrs):
            mask = addrs == addr
            exact = self.reg[self.reg["addr"] == addr]
            if not exact.empty:
                ts = exact["t"].to_numpy()
                j = np.clip(np.searchsorted(ts, t[mask], side="right") - 1, 0, len(ts) - 1)
                pid[mask] = exact["pid"].to_numpy()[j]
                method[mask] = "exact"
                continue
            ip = str(addr).rsplit(":", 1)[0]
            same_ip = self.reg.loc[self.reg["ip"] == ip, "pid"].unique()
            if len(same_ip) == 1:
                pid[mask] = same_ip[0]
                method[mask] = "ip_only"
        return pid, method

    def addr_of_player(self, pids: np.ndarray, t: np.ndarray) -> np.ndarray:
        out = np.full(len(pids), np.nan, dtype=object)
        for p in pd.unique(pids[~pd.isna(pids)]):
            regs = self.reg[self.reg["pid"] == p]
            if regs.empty:
                continue
            mask = pids == p
            ts = regs["t"].to_numpy()
            j = np.clip(np.searchsorted(ts, t[mask], side="right") - 1, 0, len(ts) - 1)
            out[mask] = regs["addr"].to_numpy()[j]
        return out


# ----------------------------------------------------------------------------
# Cheat labels
# ----------------------------------------------------------------------------

def cheat_intervals(truth: pd.DataFrame) -> pd.DataFrame:
    """Pair cheat start/stop events into [start, end] intervals.

    A row with ``start == True`` opens a cheat; the next row for the same
    (cheater, type) without ``start`` (protobuf drops False) closes it. An
    unclosed start ends at ``start + dur``; a stop without a start is taken
    to have begun ``dur`` seconds earlier.
    """
    cols = ["cheater_id", "target_id", "type", "start", "end", "how"]
    ch = truth[(truth["entry_type"] == "event") & (truth["event_type"] == "cheat")]
    if ch.empty:
        return pd.DataFrame(columns=cols)
    ch = ch.sort_values("_ts_epoch", kind="stable")
    is_start = _truthy(_col(ch, "cheat.start"))
    opened: dict[tuple, tuple[float, float, float]] = {}
    rows = []
    for st, t, cheater, target, kind, dur in zip(
        is_start, ch["_ts_epoch"], _col(ch, "cheat.cheater_id"),
        _col(ch, "cheat.target_id"), _col(ch, "cheat.type"), _col(ch, "cheat.dur"),
    ):
        dur = float(dur) if pd.notna(dur) else 0.0
        key = (cheater, kind)
        if st:
            if key in opened:  # restarted before stopping
                s, d, tg = opened.pop(key)
                rows.append((cheater, tg, kind, s, min(s + d, t), "restart"))
            opened[key] = (t, dur, target)
        elif key in opened:
            s, _, tg = opened.pop(key)
            rows.append((cheater, tg, kind, s, t, "stop"))
        else:
            rows.append((cheater, target, kind, t - dur, t, "stop_only"))
    for (cheater, kind), (s, d, tg) in opened.items():
        rows.append((cheater, tg, kind, s, s + d, "dur"))
    out = pd.DataFrame(rows, columns=cols)
    for c in ("cheater_id", "target_id"):
        out[c] = pd.to_numeric(out[c], errors="coerce")
    return out


def label_cheats(pid: np.ndarray, t: np.ndarray, iv: pd.DataFrame) -> dict:
    """Per-row cheat labels for the row's player at time ``t``."""
    n = len(pid)
    own = [set() for _ in range(n)] if len(iv) else []
    tgt = [set() for _ in range(n)] if len(iv) else []
    for r in iv.itertuples(index=False):
        in_time = (t >= r.start) & (t <= r.end)
        for i in np.flatnonzero(in_time & (pid == r.cheater_id)):
            own[i].add(str(r.type))
        if pd.notna(r.target_id) and r.target_id > 0:
            for i in np.flatnonzero(in_time & (pid == r.target_id)):
                tgt[i].add(str(r.type))
    if not len(iv):
        empty = np.full(n, "", dtype=object)
        return {"cheat_active": np.zeros(n, int), "cheat_types": empty,
                "cheat_target_active": np.zeros(n, int), "cheat_target_types": empty}
    return {
        "cheat_active": np.array([int(bool(s)) for s in own]),
        "cheat_types": np.array([";".join(sorted(s)) for s in own], dtype=object),
        "cheat_target_active": np.array([int(bool(s)) for s in tgt]),
        "cheat_target_types": np.array([";".join(sorted(s)) for s in tgt], dtype=object),
    }


# ----------------------------------------------------------------------------
# Join
# ----------------------------------------------------------------------------

def join_truth(wire: pd.DataFrame, tp: pd.DataFrame, seq_window_s: float,
               time_window_s: float) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Match wire rows to truth packet rows.

    ``wire`` needs client_addr/flow/wire_seq/timestamp/wire_is_handshake;
    ``tp`` (positional index) needs _addr/_flow/notification.seq/_ts_epoch.

    1. handshake packets: method ``handshake`` (the trace logs no handshakes);
    2. exact (client, direction, seq) within ``seq_window_s`` - nearest in
       time among unused candidates (seq is 14-bit and wraps);
    3. nearest unused truth row of the same client+direction within
       ``time_window_s``.
    Returns (truth_pos (-1 = none), method, delta_ms) aligned to ``wire``.
    """
    m = len(wire)
    pos = np.full(m, -1, dtype=np.int64)
    method = np.full(m, "unmatched", dtype=object)
    delta = np.full(m, np.nan)
    if tp.empty:
        method[:] = "no_truth"
        return pos, method, delta

    have_addr = tp["_addr"].notna().any()
    t_addr = tp["_addr"].fillna("").to_numpy(dtype=object) if have_addr \
        else np.full(len(tp), "", dtype=object)
    t_flow = tp["_flow"].to_numpy(dtype=object)
    t_seq = pd.to_numeric(tp["notification.seq"], errors="coerce").to_numpy()
    t_ts = tp["_ts_epoch"].to_numpy(dtype="float64")
    used = np.zeros(len(tp), dtype=bool)

    w_addr = wire["client_addr"].to_numpy(dtype=object) if have_addr \
        else np.full(m, "", dtype=object)
    w_flow = wire["flow"].to_numpy(dtype=object)
    w_seq = pd.to_numeric(wire["wire_seq"], errors="coerce").to_numpy()
    w_ts = pd.to_numeric(wire["timestamp"], errors="coerce").to_numpy()
    w_hs = _truthy(wire["wire_is_handshake"])
    method[w_hs] = "handshake"

    seq_index: dict[tuple, list[int]] = {}
    for g in np.flatnonzero(~np.isnan(t_seq)):
        seq_index.setdefault((t_addr[g], t_flow[g], int(t_seq[g])), []).append(int(g))

    # Pass 1: exact seq.
    for i in np.flatnonzero(~w_hs & ~np.isnan(w_seq) & ~np.isnan(w_ts)):
        best, best_dt = -1, seq_window_s
        for g in seq_index.get((w_addr[i], w_flow[i], int(w_seq[i])), ()):
            dt = abs(t_ts[g] - w_ts[i])
            if not used[g] and dt <= best_dt:
                best, best_dt = g, dt
        if best >= 0:
            used[best] = True
            pos[i], method[i], delta[i] = best, "seq", best_dt * 1000.0

    # Pass 2: nearest unused row of the same client + direction.
    groups: dict[tuple, np.ndarray] = {}
    for key, idx in pd.DataFrame({"a": t_addr, "f": t_flow}).groupby(
            ["a", "f"], sort=False).indices.items():
        idx = np.asarray(idx)
        groups[key] = idx[np.argsort(t_ts[idx], kind="stable")]
    for i in np.flatnonzero((pos < 0) & ~w_hs & ~np.isnan(w_ts)):
        idx = groups.get((w_addr[i], w_flow[i]))
        if idx is None:
            continue
        ts = t_ts[idx]
        k = int(np.searchsorted(ts, w_ts[i]))
        lo, hi, best, best_dt = k - 1, k, -1, time_window_s
        while lo >= 0 and w_ts[i] - ts[lo] <= best_dt:
            if not used[idx[lo]]:
                best, best_dt = int(idx[lo]), w_ts[i] - ts[lo]
                break
            lo -= 1
        while hi < len(ts) and ts[hi] - w_ts[i] <= best_dt:
            if not used[idx[hi]]:
                best, best_dt = int(idx[hi]), ts[hi] - w_ts[i]
                break
            hi += 1
        if best >= 0:
            used[best] = True
            pos[i], method[i], delta[i] = best, "time", best_dt * 1000.0
    return pos, method, delta


# ----------------------------------------------------------------------------
# Per-pcap assembly
# ----------------------------------------------------------------------------

def build_packets(df: pd.DataFrame, truth: pd.DataFrame | None, ident: Identity | None,
                  iv: pd.DataFrame | None, a) -> pd.DataFrame:
    wire = df[list(WIRE_DEF)].rename(columns=WIRE_DEF).reset_index(drop=True)
    wire["client_addr"] = wire["client_ip"].astype(str) + ":" + wire["client_port"].astype(str)
    w_ts = pd.to_numeric(wire["timestamp"], errors="coerce").to_numpy()

    if truth is None:
        out = wire
        out["join_method"] = "no_truth"
        out["join_delta_ms"] = np.nan
        return _canonicalize(out, PACKET_OUT_COLS)

    tp = truth[truth["entry_type"] == "packet"].reset_index(drop=True)
    tp["_addr"] = ident.truth_addr(tp)
    tp["_flow"] = np.where(_truthy(_col(tp, "incoming")), "cs", "sc")
    pos, method, delta = join_truth(wire, tp, a.seq_window_s, a.match_window_ms / 1000.0)

    tsel = tp.reindex(columns=list(PKT_TRUTH_RENAME)).rename(columns=PKT_TRUTH_RENAME)
    pad = pd.DataFrame([[np.nan] * tsel.shape[1]], columns=tsel.columns)
    tsel = pd.concat([tsel, pad], ignore_index=True).iloc[np.where(pos < 0, len(tp), pos)]
    out = pd.concat([wire, tsel.reset_index(drop=True)], axis=1)
    out["join_method"] = method
    out["join_delta_ms"] = delta

    addrs = out["client_addr"].to_numpy(dtype=object)
    out["address_id"] = [ident.id_by_addr.get(x, np.nan) for x in addrs]
    pid, how = ident.players_for(addrs, w_ts)
    out["player_id"] = pid
    out["player_name"] = [ident.names.get(int(p), "") if not np.isnan(p) else ""
                          for p in pid]
    out["player_map_method"] = how
    for k, v in label_cheats(pid, w_ts, iv).items():
        out[k] = v

    # Truth logs bunches only for incoming (cs) packets; compare against its
    # channel bunches (actor + control), not the RPC/movement annotations.
    wb = pd.to_numeric(out["wire_bunch_count"], errors="coerce")
    tb = pd.to_numeric(out["bin_channel_bunch_count"], errors="coerce")
    out["wire_bin_bunch_count_diff"] = (wb - tb).where(out["flow"] == "cs")
    return _canonicalize(out, PACKET_OUT_COLS)


def build_bunches(bunch_df: pd.DataFrame, packets: pd.DataFrame) -> pd.DataFrame:
    """Attach each wire bunch to its parent packet's context."""
    bunch = bunch_df.rename(columns={k: v for k, v in BUNCH_RENAME.items()
                                     if k in bunch_df.columns})
    ctx_cols = [c for c in BUNCH_PKT_COLS if c in packets.columns]
    ctx = packets[ctx_cols].drop_duplicates(subset=["file", "packet_no"])
    ctx = ctx.assign(packet_no=pd.to_numeric(ctx["packet_no"], errors="coerce"))
    bunch = bunch.assign(packet_no=pd.to_numeric(bunch["packet_no"], errors="coerce"))
    keep = [c for c in bunch.columns if c not in ctx_cols or c in ("file", "packet_no")]
    merged = bunch[keep].merge(ctx, on=["file", "packet_no"], how="left")
    return _canonicalize(merged, BUNCH_OUT_COLS)


def _list_join(v) -> str:
    return ";".join(str(x) for x in v) if isinstance(v, (list, tuple)) else ""


def extract_events(truth: pd.DataFrame, ident: Identity, iv: pd.DataFrame) -> pd.DataFrame:
    """Truth event rows with resolved actor and cheat label."""
    ev = truth[truth["entry_type"] == "event"].reset_index(drop=True)
    if ev.empty:
        return ev
    out = ev.reindex(columns=list(EVENT_RENAME)).rename(columns=EVENT_RENAME)
    loc = _col(ev, "movement.new_location")
    for i, axis in enumerate("xyz"):
        out[f"bin_movement_loc_{axis}"] = loc.map(
            lambda v, i=i: v[i] if isinstance(v, (list, tuple)) and len(v) > i else np.nan)
    out["bin_movement_rot"] = _col(ev, "movement.new_rotation").map(_list_join)
    vis = _col(ev, "weapon.visible_players")
    out["bin_weapon_visible_players"] = vis.map(_list_join)
    out["bin_weapon_visible_count"] = vis.map(
        lambda v: len(v) if isinstance(v, (list, tuple)) else np.nan)

    actor = pd.Series(np.nan, index=ev.index)
    for c in ACTOR_COLS:
        actor = actor.fillna(pd.to_numeric(_col(ev, c), errors="coerce"))
    pid = actor.to_numpy(dtype="float64")
    t = ev["_ts_epoch"].to_numpy(dtype="float64")
    out["actor_player_id"] = pid
    out["actor_name"] = [ident.names.get(int(p), "") if not np.isnan(p) else "" for p in pid]
    out["actor_addr"] = ident.addr_of_player(pid, t)
    for k, v in label_cheats(pid, t, iv).items():
        out[k] = v
    return _canonicalize(out, EVENT_OUT_COLS)


def _append_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, mode="a", index=False,
              header=not path.exists() or path.stat().st_size == 0)


def _report(pk: pd.DataFrame) -> None:
    flow = pk["flow"]
    jm = pd.crosstab(flow, pk["join_method"])
    print("    join methods by flow:\n      " + jm.to_string().replace("\n", "\n      "))
    err = pk["wire_bunch_parse_error"].astype(str).ne("") | pk["wire_short_packet"].astype(str).eq("True")
    bc = pd.to_numeric(pk["wire_bunch_count"], errors="coerce")
    for f in ("cs", "sc"):
        m = flow == f
        print(f"    {f}: bunch errors {int(err[m].sum()):,}/{int(m.sum()):,}, "
              f"wire bunches/pkt {bc[m].mean():.3f}")
    diff = pd.to_numeric(pk["wire_bin_bunch_count_diff"], errors="coerce").dropna()
    if len(diff):
        print(f"    cs wire-vs-truth bunch count: equal {(diff == 0).mean():.1%}, "
              f"mean diff {diff.mean():+.3f}")
    print("    player_map_method:", pk["player_map_method"].value_counts().to_dict())


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Map pcap packet fields onto the dataset's server ground truth.")
    p.add_argument("inputs", nargs="+",
                   help="pcap file(s), directories (recursively scanned) or glob patterns")
    p.add_argument("--output", default=DEFAULT_OUTPUT,
                   help="output packet CSV (default: %(default)s)")
    p.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT,
                   help="UDP server port identifying the flows (default: %(default)s)")
    p.add_argument("--truth-source", choices=("auto", "bin", "csv"), default="auto",
                   help="ground truth format next to each pcap: .bin via "
                        "ParserProtobufLogs, .csv via pandas, or auto "
                        "(.bin when parseable, else .csv) (default: %(default)s)")
    p.add_argument("--truth", default=None,
                   help="explicit trace .bin/.csv (only with a single pcap); "
                        "default: the trace next to each pcap")
    p.add_argument("--seq-window-s", type=float, default=2.0,
                   help="max |time delta| for an exact seq match (default: %(default)s)")
    p.add_argument("--match-window-ms", type=float, default=50.0,
                   help="time window for the nearest-time fallback (default: %(default)s)")
    p.add_argument("--no-bunches", action="store_true", help="skip the bunch CSV")
    p.add_argument("--no-events", action="store_true", help="skip the event CSV")
    a = p.parse_args(argv)

    pcaps = discover_files(a.inputs)
    if not pcaps:
        print(f"No .pcap files found under {a.inputs}")
        return 1
    if a.truth and len(pcaps) != 1:
        print("--truth can only be used with a single pcap")
        return 1
    print(f"Found {len(pcaps)} pcap file(s)")

    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    bunch_out = out.with_name(out.stem + "_bunches.csv")
    events_out = out.with_name(out.stem + "_events.csv")
    for path in (out, bunch_out, events_out):
        path.unlink(missing_ok=True)

    adaptor = PcapAdaptor(server_port=a.server_port)
    totals = {"packets": 0, "bunches": 0, "events": 0, "errors": 0}
    start_all = time.monotonic()

    for n, pcap in enumerate(pcaps, start=1):
        t0 = time.monotonic()
        trace = Path(a.truth) if a.truth else find_truth(pcap)
        truth = ident = iv = None
        if trace is None:
            print(f"[{n}/{len(pcaps)}] {pcap}: WARNING no trace_* ground truth next to it")
        else:
            try:
                truth, used = load_truth(trace, a.truth_source)
                ident, iv = Identity(truth), cheat_intervals(truth)
                print(f"[{n}/{len(pcaps)}] {pcap} -> {trace.name} ({used}, "
                      f"{len(truth):,} rows, {len(iv)} cheat intervals)", flush=True)
            except (FileNotFoundError, ValueError) as exc:
                print(f"[{n}/{len(pcaps)}] {pcap}: WARNING cannot load truth: {exc}")

        df, bunch_df, counts = adaptor.process_file(pcap)
        packets = build_packets(df, truth, ident, iv, a)
        _append_csv(packets, out)
        if not a.no_bunches and not bunch_df.empty:
            _append_csv(build_bunches(bunch_df, packets), bunch_out)
        if not a.no_events and truth is not None:
            ev = extract_events(truth, ident, iv)
            if not ev.empty:
                _append_csv(ev, events_out)
                totals["events"] += len(ev)

        for k in ("packets", "bunches", "errors"):
            totals[k] += counts[k]
        print(f"    {counts['packets']:,} packets, {counts['bunches']:,} bunches "
              f"({time.monotonic() - t0:.1f}s)", flush=True)
        _report(packets)
        del df, bunch_df, packets, truth

    print(f"\nProcessed {len(pcaps)} pcap(s): {totals['packets']:,} packets, "
          f"{totals['bunches']:,} bunches, {totals['errors']:,} decode errors "
          f"in {time.monotonic() - start_all:.0f}s")
    print(f"Wrote {out}")
    if bunch_out.exists():
        print(f"Wrote {bunch_out}")
    if events_out.exists():
        print(f"Wrote {events_out} ({totals['events']:,} event rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
