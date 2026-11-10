# commands/actors.py
"""Actor / channel resolution helpers shared across command modules."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from core.names.ename import EName
from net.guid.package_map_client import get_net_guid_cache, use_package_map_state
from net.guid.static_field_mapping import get_class_max, get_field_name
from net.net_serialization import write_network_guid
from net.rpc.sender import build_actor_rpc_packet
from serialization.bit_writer import FBitWriter

if TYPE_CHECKING:
    from net.connection import NetConnection


# ---------------------------------------------------------------------------
# Runtime command state (per-connection extension)
# ---------------------------------------------------------------------------

def get_runtime_cmd_state(conn: NetConnection) -> dict:
    return conn.get_extension("runtime_cmd_state", dict)


# ---------------------------------------------------------------------------
# Actor class resolution
# ---------------------------------------------------------------------------

def _extract_class_name_from_path(path: str | None) -> str:
    if not path:
        return ""
    value = path
    if "." in value:
        value = value.rsplit(".", 1)[-1]
    elif "/" in value:
        value = value.rsplit("/", 1)[-1]
    if value.startswith("Default__"):
        value = value[9:]
    return value


def _get_new_actor(channel: object) -> object | None:
    spawn_data = getattr(channel, "_spawn_data", None)
    if spawn_data is None:
        return None
    new_actor = getattr(spawn_data, "new_actor", None)
    return new_actor


def infer_actor_class_name(conn: NetConnection, channel: object) -> str:
    new_actor = _get_new_actor(channel)
    if new_actor is None:
        return ""
    archetype_guid = int(getattr(new_actor, "archetype_guid", 0) or 0)
    if archetype_guid <= 0:
        return ""
    try:
        with use_package_map_state(conn.package_map_state):
            cache = get_net_guid_cache()
            path = cache.get_full_path(archetype_guid) or cache.get_path(archetype_guid) or ""
    except Exception:
        return ""
    return _extract_class_name_from_path(path)


def get_actor_guid(channel: object) -> int | None:
    new_actor = _get_new_actor(channel)
    if new_actor is None:
        return None
    value = int(getattr(new_actor, "actor_guid", 0) or 0)
    return value if value > 0 else None


# ---------------------------------------------------------------------------
# Actor channel search
# ---------------------------------------------------------------------------

def resolve_class_name(conn: NetConnection, channel: object) -> str:
    """Try _actor_class_path first, then fall back to archetype GUID lookup."""
    path = getattr(channel, "_actor_class_path", None)
    if isinstance(path, str) and path:
        name = _extract_class_name_from_path(path)
        if name:
            return name
    return infer_actor_class_name(conn, channel)


def find_actor_channels(conn: NetConnection, class_match: str) -> list[tuple[int, str]]:
    """Find all actor channels whose class name or path contains *class_match*"""
    needle = class_match.lower()
    matches: list[tuple[int, str]] = []
    for idx, channel in enumerate(conn.channels):
        if channel is None or channel.ch_name != EName.Actor:
            continue
        class_name = resolve_class_name(conn, channel)
        class_path = (getattr(channel, "_actor_class_path", None) or "").lower()
        if needle in class_name.lower() or needle in class_path:
            matches.append((idx, class_name))
    return matches


def find_player_controller_channel(conn: NetConnection) -> tuple[int, str] | None:
    results = find_actor_channels(conn, "PlayerController")
    if not results:
        return None
    # Prefer a result with a resolved class name
    for ch_index, class_name in results:
        if class_name:
            return ch_index, class_name
    return results[0][0], "PlayerController"


# ---------------------------------------------------------------------------
# Class-net-cache / field resolution
# ---------------------------------------------------------------------------

_CLASS_CACHE_DATA: dict | None = None


def get_class_cache_data() -> dict:
    global _CLASS_CACHE_DATA
    if _CLASS_CACHE_DATA is None:
        cache_path = Path(__file__).resolve().parent.parent / "net" / "guid" / "data" / "class_net_cache.json"
        try:
            _CLASS_CACHE_DATA = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _CLASS_CACHE_DATA = {}
    return _CLASS_CACHE_DATA


def get_parent_class(class_name: str) -> str | None:
    data = get_class_cache_data()
    classes = data.get("classes", {})
    info = classes.get(class_name)
    if isinstance(info, dict):
        parent = info.get("parent")
        if isinstance(parent, str) and parent:
            return parent
    return None


def find_field_index(class_name: str, field_name: str) -> int | None:
    class_max = get_class_max(class_name)
    if class_max is None:
        return None
    for index in range(class_max + 1):
        if get_field_name(class_name, index) == field_name:
            return index
    return None


def resolve_rpc_field(class_name: str, rpc_name: str) -> tuple[str, int, int] | None:
    """Walk class hierarchy to find *rpc_name*"""
    current = class_name
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        field_max = get_class_max(current)
        field_index = find_field_index(current, rpc_name)
        if field_max is not None and field_index is not None:
            return current, field_index, field_max
        current = get_parent_class(current)
    return None


def build_ack_possession_packet(
    conn: NetConnection,
    pawn_guid: int,
    *,
    controller_ch: int | None = None,
    controller_class: str = "",
) -> tuple[bytes, str, int, int]:
    """Build a ServerAcknowledgePossession RPC packet"""
    if pawn_guid <= 0:
        raise ValueError(f"Invalid pawn GUID: {pawn_guid}")

    if controller_ch is None or not controller_class:
        resolved = find_player_controller_channel(conn)
        if resolved is None:
            raise ValueError("Unable to resolve PlayerController channel")
        found_ch, found_class = resolved
        if controller_ch is None:
            controller_ch = found_ch
        if not controller_class:
            controller_class = found_class

    rpc = resolve_rpc_field(controller_class, "ServerAcknowledgePossession")
    if rpc is None:
        raise ValueError(f"ServerAcknowledgePossession not found in class hierarchy: {controller_class}")
    resolved_class, field_index, field_max = rpc

    payload_writer = FBitWriter(allow_resize=True)
    payload_writer.write_bit(True)  # param present
    write_network_guid(payload_writer, pawn_guid)

    packet = build_actor_rpc_packet(
        conn=conn,
        ch_index=controller_ch,
        field_index=field_index,
        field_max=field_max,
        rpc_payload=payload_writer.get_buffer(),
        rpc_payload_bits=payload_writer.num_bits,
        reliable=True,
    )
    return packet, resolved_class, field_index, controller_ch


def try_auto_ack_possession(
    conn: NetConnection, pawn_ch: int,
) -> tuple[bytes, str, int, int, int] | None:
    """Build an ack-possession packet if we haven't already acked this pawn."""
    channel = conn.channels[pawn_ch]
    if channel is None:
        return None
    pawn_guid = get_actor_guid(channel)
    if pawn_guid is None:
        return None

    state = get_runtime_cmd_state(conn)
    acked = state.get("acked_pawn_guids")
    if not isinstance(acked, set):
        acked = set()
        state["acked_pawn_guids"] = acked
    if pawn_guid in acked:
        return None

    packet, resolved_class, field_index, controller_ch = build_ack_possession_packet(
        conn, pawn_guid,
    )
    acked.add(pawn_guid)
    return packet, resolved_class, field_index, controller_ch, pawn_guid
