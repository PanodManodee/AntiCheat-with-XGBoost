# net/channels/channel_registry.py
"""Channel registry for runtime channel type/factory resolution."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, TYPE_CHECKING

from core.names.ename import EName
from net.channels.base_channel import Channel
from net.channels.channel_types import EChannelType

if TYPE_CHECKING:
    from net.connection import NetConnection

ChannelFactory = Callable[['NetConnection', int, EName], Channel]


@dataclass(frozen=True, slots=True)
class ChannelRegistration:
    ch_type: EChannelType
    factory: ChannelFactory
    b_server_open: bool = True
    b_client_open: bool = False


_CHANNEL_REGISTRY: dict[EName, ChannelRegistration] = {}
_DEFAULT_CHANNELS_REGISTERED = False


def register_channel(
    ch_name: EName,
    ch_type: EChannelType,
    factory: ChannelFactory,
    *,
    b_server_open: bool = True,
    b_client_open: bool = False,
    replace: bool = True,
) -> None:
    if not replace and ch_name in _CHANNEL_REGISTRY:
        raise ValueError(f"Channel is already registered: {ch_name!r}")
    _CHANNEL_REGISTRY[ch_name] = ChannelRegistration(
        ch_type=ch_type, factory=factory,
        b_server_open=b_server_open, b_client_open=b_client_open,
    )


def unregister_channel(ch_name: EName) -> None:
    _CHANNEL_REGISTRY.pop(ch_name, None)


def get_registration(ch_name: EName) -> Optional[ChannelRegistration]:
    return _CHANNEL_REGISTRY.get(ch_name)


def get_channel_type(ch_name: EName) -> EChannelType:
    registration = _CHANNEL_REGISTRY.get(ch_name)
    if registration is None:
        return EChannelType.CHTYPE_None
    return registration.ch_type


def create_channel(connection: 'NetConnection', ch_name: EName, ch_index: int) -> Channel:
    registration = _CHANNEL_REGISTRY.get(ch_name)
    if registration is None:
        supported = ", ".join(name.name for name in list_registered_channels())
        raise NotImplementedError(f"Unknown channel name: {ch_name!r} (registered: {supported})")
    return registration.factory(connection, ch_index, ch_name)


def list_registered_channels() -> tuple[EName, ...]:
    return tuple(_CHANNEL_REGISTRY.keys())


def register_default_channels() -> None:
    global _DEFAULT_CHANNELS_REGISTERED
    if _DEFAULT_CHANNELS_REGISTERED:
        return

    from net.channels.actor.channel import ActorChannel
    from net.channels.control.channel import ControlChannel
    from net.channels.voice_channel import VoiceChannel

    register_channel(EName.Control, EChannelType.CHTYPE_Control, ControlChannel, b_server_open=False, b_client_open=True)
    register_channel(EName.Actor, EChannelType.CHTYPE_Actor, ActorChannel, b_server_open=True, b_client_open=False)
    register_channel(EName.Voice, EChannelType.CHTYPE_Voice, VoiceChannel, b_server_open=True, b_client_open=True)
    _DEFAULT_CHANNELS_REGISTERED = True


def ensure_default_channels_registered() -> None:
    register_default_channels()
