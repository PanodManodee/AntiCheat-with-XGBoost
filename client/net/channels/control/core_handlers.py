# net/channels/control/core_handlers.py
"""Core NMT control handlers."""
from __future__ import annotations

from typing import TYPE_CHECKING

from net.packets.control import NetControlMessageType, NMT

if TYPE_CHECKING:
    from .channel import ControlChannel, ControlMessageHandler
    from net.connection import NetConnection
    from net.packets.in_bunch import FInBunch
    from net.state.session_state import SessionState


def get_handlers() -> dict[int, ControlMessageHandler]:
    return {
        int(NetControlMessageType.Challenge): handle_challenge,
        int(NetControlMessageType.Login): handle_login,
        int(NetControlMessageType.Netspeed): handle_netspeed,
        int(NetControlMessageType.Welcome): handle_welcome,
        int(NetControlMessageType.Join): handle_join,
        int(NetControlMessageType.Failure): handle_failure,
        int(NetControlMessageType.Hello): handle_hello,
        int(NetControlMessageType.CloseReason): handle_close_reason,
    }


def handle_challenge(channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', session: 'SessionState') -> None:
    bunch.read_fstring()  # client_response_echo
    if bunch.get_bits_left() >= 40:
        try:
            bunch.read_fstring()  # challenge_string
        except RuntimeError:
            pass

    if session.login_params:
        params = session.login_params
        session.player_id = params.get("PlayerId", "")
        channel.final_packets.append(NMT.Login.Get(
            connection,
            ClientResponse="0",
            URL=params.get("URL", ""),
            PlayerId=params.get("PlayerId", ""),
        ))
        session.login_params = None


def handle_login(_channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    NMT.Login.Received(connection, bunch)


def handle_netspeed(_channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    NMT.Netspeed.Received(connection, bunch)


def handle_welcome(channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    NMT.Welcome.Received(connection, bunch)
    channel.final_packets.append(NMT.Netspeed.Get(connection, NetSpeed=1200000))
    channel.final_packets.append(NMT.Join.Get(connection))


def handle_join(_channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    NMT.Join.Received(connection, bunch)


def handle_failure(channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    reason = NMT.Failure.Received(connection, bunch)
    connection.close_reason = reason
    connection.b_closed = True
    if connection.channels[0] is not None:
        channel.final_packets.append(connection.create_disconnect_packet())


def handle_hello(_channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    NMT.Hello.Received(connection, bunch)


def handle_close_reason(channel: 'ControlChannel', connection: 'NetConnection', bunch: 'FInBunch', _session: 'SessionState') -> None:
    reason = NMT.CloseReason.Received(connection, bunch)
    connection.close_reason = reason
    connection.b_closed = True
    if connection.channels[0] is not None:
        channel.final_packets.append(connection.create_disconnect_packet())
