"""Load the per-match server ground truth that ships next to each pcap.

Every ``dataset/<Session>/<Match>/Server/`` directory holds::

    capture_server_<ts>.pcap      wire capture
    trace_server_<ts>.bin         protobuf RingBufferLog (authoritative)
    trace_server_<ts>.csv         the same log exported to CSV (nested reprs)

``find_truth`` resolves the trace belonging to a pcap and ``load_truth`` turns
it into one flat DataFrame with dotted column names (``notification.seq``,
``weapon.target_id`` ...) plus per-packet features summarising the truth
``bunches`` list (``bin_bunch_count``, ``bin_rpc_funcs`` ...).

Source selection (``source``):
  * ``bin``  - parse the .bin with ``ParserProtobufLogs`` (needs ``protobuf``).
  * ``csv``  - parse the sibling .csv with pandas only. The nested cells are
               Python reprs; they are read with ``ast.literal_eval`` after the
               ``datetime.datetime(...)`` calls are rewritten to epoch floats,
               so nothing is ever ``eval``-ed.
  * ``auto`` - ``bin`` when the parser imports and the .bin exists, else ``csv``.

The two exports come from different logger/parser versions; known key drift
is normalised to the .bin naming (``is_blind`` -> ``blind``, ``tsc`` ->
``ts_client``, ``tssrv`` -> ``ts_server``, ``location``/``rotation`` ->
``new_location``/``new_rotation``). The .csv lacks ``cheat.in_``,
``weapon.cartridge_id`` and ``new_player.update_ip_port``; those stay blank. The .csv additionally carries
``notification.address`` (the client ``ip:port``, outgoing rows only); the
client address is otherwise recovered from ``header.ids.ipaddress`` +
``new_address`` events.
"""
from __future__ import annotations

import ast
import re
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# Columns holding nested dict/list values in both exports.
NESTED_COLS = [
    "header", "notification", "new_address", "new_player", "phase_event",
    "health", "movement", "cheat", "weapon",
]
BUNCHES_COL = "bunches"

# Older-export key -> current key (applied at any nesting level).
KEY_ALIASES = {
    "is_blind": "blind", "tsc": "ts_client", "tssrv": "ts_server",
    "location": "new_location", "rotation": "new_rotation",
}

BUNCH_FEATURE_COLS = [
    "bin_bunch_count", "bin_channel_bunch_count", "bin_actor_bunch_count",
    "bin_actor_classes",
    "bin_ctrl_msgs", "bin_rpc_count", "bin_rpc_funcs",
    "bin_move_count", "bin_move_dt_sum",
    "bin_move_loc_x", "bin_move_loc_y", "bin_move_loc_z",
    "bin_move_vel_x", "bin_move_vel_y", "bin_move_vel_z",
    "bin_move_inv_ts_count",
]


def _with_ext(stem: Path, ext: str) -> Path:
    """``stem`` + ``ext``. Trace names contain dots (``..._12.36.06``), so
    ``Path.with_suffix`` would clobber the timestamp."""
    return stem.parent / f"{stem.name}{ext}"


# ----------------------------------------------------------------------------
# Locating the trace for a pcap
# ----------------------------------------------------------------------------

def _norm_name(name: str) -> str:
    """Timestamp-only form of a trace/capture name, ignoring -/_ and suffixes
    such as ``_merged`` (``trace_server_2026.02.20_15.36.45_merged``)."""
    return re.sub(r"[^0-9.]", "", name)


def trace_stem_for(pcap: Path) -> str | None:
    """``capture_server_<ts>.pcap`` -> ``trace_server_<ts>`` (None if not a capture)."""
    m = re.match(r"^capture_(.+)\.pcap(?:ng)?$", pcap.name, re.IGNORECASE)
    return f"trace_{m.group(1)}" if m else None


def find_truth(pcap: Path) -> Path | None:
    """Return the trace (without suffix) next to ``pcap``.

    Exact name first; otherwise a trace in the same directory whose timestamp
    matches (e.g. ``*_merged``). The returned path has no suffix; ``.bin`` /
    ``.csv`` are chosen by ``load_truth``.
    """
    stem = trace_stem_for(pcap)
    if stem is None:
        return None
    exact = pcap.parent / stem
    if _with_ext(exact, ".bin").exists() or _with_ext(exact, ".csv").exists():
        return exact
    want = _norm_name(stem)
    cands = sorted(
        {p.parent / p.stem for p in pcap.parent.glob("trace_*")
         if p.suffix.lower() in (".bin", ".csv") and _norm_name(p.stem) == want}
    )
    return cands[0] if cands else None


# ----------------------------------------------------------------------------
# Raw loaders
# ----------------------------------------------------------------------------

def bin_parser_available() -> bool:
    try:
        from ParserProtobufLogs.parser_utils import RingBufferParser  # noqa: F401
    except Exception:  # noqa: BLE001 - missing package or protobuf
        return False
    return True


def _load_bin(path: Path) -> pd.DataFrame:
    from ParserProtobufLogs.parser_utils import RingBufferParser

    df = RingBufferParser.from_file(str(path)).to_dataframe()
    return df.drop(columns=["payload"], errors="ignore")


_DT_RE = re.compile(r"datetime\.datetime\(([^()]*)\)")


def _dt_to_epoch(m: re.Match) -> str:
    args = [a.strip() for a in m.group(1).split(",") if a.strip()]
    nums = [int(a) for a in args if "=" not in a]
    return repr(datetime(*nums, tzinfo=timezone.utc).timestamp())


def safe_literal(s):
    """Parse a Python-repr cell (dict/list) without eval; NaN-safe."""
    if not isinstance(s, str) or not s:
        return np.nan
    if "datetime" in s:
        s = _DT_RE.sub(_dt_to_epoch, s)
    try:
        return ast.literal_eval(s)
    except (ValueError, SyntaxError):
        return np.nan


def _load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
    df = df.drop(columns=["payload"], errors="ignore")
    for c in NESTED_COLS + [BUNCHES_COL]:
        if c in df.columns:
            df[c] = df[c].map(safe_literal)
    for c in ("ind", "frame"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in ("outgoing", "incoming"):
        if c in df.columns:
            df[c] = df[c].map({"True": True, "False": False})
    return df


# ----------------------------------------------------------------------------
# Flattening
# ----------------------------------------------------------------------------

def _flatten_dict(d: dict, prefix: str, out: dict) -> None:
    for k, v in d.items():
        k = KEY_ALIASES.get(k, k)
        key = f"{prefix}.{k}"
        if isinstance(v, dict):
            _flatten_dict(v, key, out)
        else:
            out[key] = v


def _flatten_nested(df: pd.DataFrame) -> pd.DataFrame:
    parts = []
    for col in NESTED_COLS:
        if col not in df.columns:
            continue
        rows = {}
        for idx, v in df[col].items():
            if isinstance(v, dict):
                flat: dict = {}
                _flatten_dict(v, col, flat)
                rows[idx] = flat
        if rows:
            parts.append(pd.DataFrame.from_dict(rows, orient="index"))
    base = df.drop(columns=[c for c in NESTED_COLS if c in df.columns])
    if parts:
        base = base.join(pd.concat(parts, axis=1))
    return base


_VEC_RE = re.compile(r"X=(-?[\d.eE+-]+)\s+Y=(-?[\d.eE+-]+)\s+Z=(-?[\d.eE+-]+)")
_INSTANCE_RE = re.compile(r"_\d+$")


def _vec(s) -> tuple[float, float, float]:
    m = _VEC_RE.search(s) if isinstance(s, str) else None
    return tuple(float(x) for x in m.groups()) if m else (np.nan,) * 3


def bunch_features(bunches) -> dict:
    """Summarise one truth packet's ``bunches`` list into flat features."""
    if not isinstance(bunches, list):
        return {}
    actors: list[str] = []
    ctrl: list[str] = []
    rpcs: list[str] = []
    n_actor = n_move = n_inv = 0
    dt_sum = 0.0
    loc = vel = (np.nan,) * 3
    for b in bunches:
        if not isinstance(b, dict) or not b:
            continue
        kind, body = next(iter(b.items()))
        body = body if isinstance(body, dict) else {}
        if kind == "bunch_actor_channel":
            n_actor += 1
            name = str(body.get("actor_name", "")).split(" ", 1)[0]
            if name:
                actors.append(_INSTANCE_RE.sub("", name))
        elif kind == "control_channel":
            ctrl.append(str(body.get("messagetype", "")))
        elif kind == "received_rpc":
            rpcs.append(str(body.get("func", "")))
        elif kind == "movement_srv_rcvd":
            n_move += 1
            dt_sum += float(body.get("dt") or 0.0)
            loc = _vec(body.get("loc"))
            vel = _vec(body.get("velocity"))
        elif kind == "movement_inv_timestamp":
            n_inv += 1
    return {
        "bin_bunch_count": len(bunches),
        # Actual channel bunches (actor + control); the other records
        # (RPC / movement) annotate those bunches and are not bunches.
        "bin_channel_bunch_count": n_actor + len(ctrl),
        "bin_actor_bunch_count": n_actor,
        "bin_actor_classes": ";".join(sorted(set(actors))),
        "bin_ctrl_msgs": ";".join(ctrl),
        "bin_rpc_count": len(rpcs),
        "bin_rpc_funcs": ";".join(rpcs),
        "bin_move_count": n_move,
        "bin_move_dt_sum": dt_sum,
        "bin_move_loc_x": loc[0], "bin_move_loc_y": loc[1], "bin_move_loc_z": loc[2],
        "bin_move_vel_x": vel[0], "bin_move_vel_y": vel[1], "bin_move_vel_z": vel[2],
        "bin_move_inv_ts_count": n_inv,
    }


def _add_bunch_features(df: pd.DataFrame) -> pd.DataFrame:
    if BUNCHES_COL not in df.columns:
        return df
    feats = {idx: bunch_features(v) for idx, v in df[BUNCHES_COL].items()
             if isinstance(v, list)}
    out = df.drop(columns=[BUNCHES_COL])
    if feats:
        out = out.join(pd.DataFrame.from_dict(feats, orient="index"))
    return out


# ----------------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------------

def load_truth(trace: Path, source: str = "auto") -> tuple[pd.DataFrame, str]:
    """Load ``trace`` (a path with or without .bin/.csv suffix).

    Returns ``(flat_df, source_used)``. ``flat_df`` has the dotted columns,
    the ``bin_*`` bunch features, ``session``/``match``/``file`` and
    ``_ts_epoch`` (float seconds, UTC).
    """
    trace = Path(trace)
    if trace.suffix.lower() in (".bin", ".csv"):
        if source == "auto":
            source = trace.suffix.lower()[1:]
        trace = trace.parent / trace.stem
    bin_path, csv_path = _with_ext(trace, ".bin"), _with_ext(trace, ".csv")

    if source == "auto":
        source = "bin" if bin_path.exists() and bin_parser_available() else "csv"
    if source == "bin":
        if not bin_path.exists():
            raise FileNotFoundError(bin_path)
        raw, used = _load_bin(bin_path), bin_path
    elif source == "csv":
        if not csv_path.exists():
            raise FileNotFoundError(csv_path)
        raw, used = _load_csv(csv_path), csv_path
    else:
        raise ValueError(f"unknown truth source {source!r}")

    raw = raw.reset_index(drop=True)
    df = _add_bunch_features(_flatten_nested(raw))
    # protobuf omits default values (0 / False) in the .bin parse while the
    # .csv export writes them; make cheat rows agree on both.
    is_cheat = df.get("event_type") == "cheat"
    if is_cheat is not None and is_cheat.any():
        for col, default in (("cheat.target_id", 0), ("cheat.start", False)):
            if col not in df.columns:
                df[col] = np.nan
            df[col] = df[col].astype(object)
            df.loc[is_cheat & df[col].isna(), col] = default
    if "notification.address" in df.columns:
        # The CSV export writes '' for incoming rows; treat as missing.
        df["notification.address"] = df["notification.address"].replace("", np.nan)
    df["session"] = used.parents[2].name if len(used.parents) > 2 else ""
    df["match"] = used.parents[1].name if len(used.parents) > 1 else ""
    df["file"] = used.name
    ts = pd.to_datetime(df["ts"], utc=True, errors="coerce", format="ISO8601")
    df["_ts_epoch"] = (ts - pd.Timestamp(0, tz="UTC")).dt.total_seconds()
    return df, source
