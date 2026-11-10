# commands/nick.py
"""The nick command — change player display name via ServerChangeName RPC.

Usage::

    nick NewPlayerName
    nick "Name With Spaces"
"""
from __future__ import annotations

from commands.actors import (
    find_player_controller_channel,
    resolve_rpc_field,
)
from commands.base import CommandContext, cmd_log, register
from net.rpc.sender import build_actor_rpc_packet
from serialization.bit_writer import FBitWriter


def _cmd_nick(ctx: CommandContext, tokens: list[str]) -> tuple[bool, bool]:
    if len(tokens) < 2:
        raise ValueError("Usage: nick <new_name>")

    new_name = " ".join(tokens[1:])
    conn = ctx.conn

    result = find_player_controller_channel(conn)
    if result is None:
        raise ValueError("PlayerController channel not found")
    pc_ch, class_name = result

    rpc = resolve_rpc_field(class_name, "ServerChangeName")
    if rpc is None:
        raise ValueError(f"ServerChangeName RPC not found for class: {class_name}")
    resolved_class, field_index, field_max = rpc

    # RPC payload: single FString param (non-bool → 1-bit present flag + value)
    w = FBitWriter(allow_resize=True)
    w.write_bit(True)
    w.serialize_fstring(new_name)

    packet = build_actor_rpc_packet(
        conn=conn, ch_index=pc_ch,
        field_index=field_index, field_max=field_max,
        rpc_payload=w.get_buffer(), rpc_payload_bits=w.num_bits,
        reliable=True,
    )
    ctx.sock.sendto(packet, ctx.server_addr)
    cmd_log(f"[->] CMD nick ({len(packet)}) | name={new_name!r} ch={pc_ch} class={resolved_class}")
    return True, False


register("nick", _cmd_nick)
