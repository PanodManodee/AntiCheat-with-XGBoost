# net/channels/actor/handlers/__init__.py
"""Actor channel handlers — RPC and spawn processors."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from net.channels.actor.channel import ActorChannel
    from net.connection import NetConnection
    from net.replication import SpawnBunchData

RpcHandler = Callable[['ActorChannel', dict[str, Any]], None]
SpawnProcessor = Callable[[str, 'SpawnBunchData', 'NetConnection', bytes], bool]

_DEFAULT_RPC_HANDLERS: dict[str, RpcHandler] = {
}

_DEFAULT_SPAWN_PROCESSORS: list[SpawnProcessor] = [
]


def get_default_rpc_handlers() -> dict[str, RpcHandler]:
    return dict(_DEFAULT_RPC_HANDLERS)


def get_default_spawn_processors() -> list[SpawnProcessor]:
    return list(_DEFAULT_SPAWN_PROCESSORS)
