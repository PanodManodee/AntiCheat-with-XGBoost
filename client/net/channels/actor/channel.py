# net/channels/actor/channel.py
"""Actor channel - spawn bunch handling, RPC dispatch."""
from __future__ import annotations

from math import ceil, log2
from typing import TYPE_CHECKING, Any, Callable, Optional

from net.channels.actor.handlers import get_default_rpc_handlers, get_default_spawn_processors
from net.channels.actor.handlers.class_path import extract_class_name, is_class_known, resolve_actor_class_path
from net.channels.base_channel import Channel
from net.guid.package_map_client import get_net_guid_cache
from net.guid.static_field_mapping import get_field_name
from net.net_serialization import read_network_guid
from net.replication import parse_spawn_bunch, SpawnBunchData
from net.replication.content_block import iter_content_blocks
from net.replication.custom_delta import CustomDelta
from net.replication.rep_layout import RepLayoutRegistry
from net.rpc import RPC
from net.error_reporter import report_exception, PARSE_EXCEPTIONS
from serialization.bit_reader import FBitReader

if TYPE_CHECKING:
    from net.connection import NetConnection
    from net.packets.in_bunch import FInBunch

ActorRpcHandler = Callable[['ActorChannel', dict[str, Any]], None]


class ActorChannel(Channel):
    __slots__ = (
        '_chat_callback', '_actor_class_path', '_serialize_int_max',
        '_actor_guids', '_spawn_data', '_rep_layout',
        '_rpc_handlers', '_spawn_processors',
    )

    def __init__(self, connection: 'NetConnection', ch_index: int, ch_name: int) -> None:
        super().__init__(connection, ch_index, ch_name)
        self._chat_callback: Optional[Callable[[dict], None]] = None
        self._actor_class_path: Optional[str] = None
        self._serialize_int_max: Optional[int] = None
        self._actor_guids: list[int] = []
        self._rep_layout = None
        self._spawn_data: Optional[SpawnBunchData] = None
        self._rpc_handlers: dict[str, ActorRpcHandler] = get_default_rpc_handlers()
        self._spawn_processors = get_default_spawn_processors()

    def set_chat_callback(self, callback: Callable[[dict], None]) -> None:
        self._chat_callback = callback

    def register_rpc_handler(self, rpc_name: str, handler: ActorRpcHandler) -> None:
        self._rpc_handlers[rpc_name] = handler

    def unregister_rpc_handler(self, rpc_name: str) -> None:
        self._rpc_handlers.pop(rpc_name, None)

    def set_actor_class(self, class_path: str) -> None:
        self._actor_class_path = class_path
        self._serialize_int_max = get_net_guid_cache().get_serialize_int_max(class_path)

        name = extract_class_name(class_path)
        if name:
            self._rep_layout = RepLayoutRegistry.get(name)

        if not is_class_known(name):
            print(f"[Actor] Ch={self.ch_index} | UNKNOWN: {name}")

    def on_open_guids(self, guids: list[int]) -> None:
        self.set_actor_guids(guids)

    def set_actor_guids(self, guids: list[int]) -> None:
        self._actor_guids = guids.copy()
        cache = get_net_guid_cache()
        class_path = resolve_actor_class_path(guids, cache.get_path)
        if class_path:
            self.set_actor_class(class_path)

    @property
    def spawn_data(self) -> Optional[SpawnBunchData]:
        return self._spawn_data

    @property
    def rep_layout(self) -> Any:
        return self._rep_layout

    @property
    def serialize_int_max(self) -> Optional[int]:
        return self._serialize_int_max

    # ---- Bunch processing ----

    def received_bunch(self, connection, bunch: 'FInBunch') -> None:
        if bunch.bOpen:
            self._handle_spawn_bunch(bunch.get_buffer(), bunch.bHasMustBeMappedGUIDs)
        else:
            if bunch.bHasMustBeMappedGUIDs:
                try:
                    num_guids = bunch.read_uint16()
                    for _ in range(num_guids):
                        read_network_guid(bunch)
                except PARSE_EXCEPTIONS as exc:
                    report_exception(f"ActorChannel must-be-mapped GUIDs: {exc}")
                    return
            self._process_content_blocks(bunch)

    def _process_content_blocks(self, bunch: 'FInBunch') -> None:
        for block in iter_content_blocks(bunch):
            try:
                if not block.has_payload:
                    continue

                if block.header.is_actor:
                    actor_class = extract_class_name(self._actor_class_path)
                    self._process_block_payload(
                        block, actor_class, self._rep_layout, self._serialize_int_max,
                    )
                elif not block.header.is_deleted:
                    self._process_subobject_block(block)
            except PARSE_EXCEPTIONS as exc:
                report_exception(f"ActorChannel content block Ch={self.ch_index}: {exc}")
                break

    def _process_block_payload(self, block, class_name, rep_layout, serialize_int_max) -> None:
        reader = FBitReader(block.payload_data, block.payload_bits)
        if block.header.has_rep_layout:
            if not rep_layout:
                return
            if not rep_layout.receive_properties(reader, self.connection).success:
                return
        if serialize_int_max is not None and class_name and not reader.at_end():
            self._process_fields(reader, class_name, serialize_int_max)

    def _process_subobject_block(self, block) -> None:
        cache = get_net_guid_cache()
        class_path = self._resolve_subobject_class(block.header, cache)
        if not class_path:
            return
        class_name = extract_class_name(class_path)
        if not class_name:
            return
        rep_layout = RepLayoutRegistry.get(class_name)
        serialize_int_max = cache.get_serialize_int_max(class_path)
        self._process_block_payload(block, class_name, rep_layout, serialize_int_max)

    @staticmethod
    def _resolve_subobject_class(header, cache) -> Optional[str]:
        if header.class_guid:
            return cache.get_path(header.class_guid)
        # extract_class_name() will extract the last component (e.g. "CharacterMovement0")
        # which won't match any registered class — the block is safely skipped.
        if header.object_guid:
            return cache.get_full_path(header.object_guid)
        return None

    def _process_fields(self, payload: FBitReader, class_name: str, field_max: int) -> None:
        effective_max = max(field_max + 1, 2)

        while payload.get_bits_left() > 0:
            try:
                field_index = payload.read_int(effective_max)
                if field_index > field_max:
                    return
                field_bits = payload.read_uint32_packed()
                field_payload = FBitReader(payload.serialize_bits(field_bits), field_bits)
                self._process_field(class_name, field_index, field_payload)
            except PARSE_EXCEPTIONS:
                return

    def _process_field(self, class_name: str, field_index: int, payload: FBitReader) -> None:
        field_name = get_field_name(class_name, field_index)
        if not field_name:
            return

        delta_result = CustomDelta.receive(field_name, payload, self.connection)
        if delta_result is not None:
            return

        result = RPC.parse(field_name, payload)
        if result:
            self._dispatch_rpc(field_name, result)

    def _dispatch_rpc(self, rpc_name: str, data: dict[str, Any]) -> None:
        handler = self._rpc_handlers.get(rpc_name)
        if handler is not None:
            handler(self, data)

    # ---- Spawn bunch processing ----

    def _handle_spawn_bunch(self, data: bytes, has_must_be_mapped_guids: bool = False) -> None:
        class_hint = self._rep_layout.class_name if self._rep_layout else self._actor_class_path
        self._spawn_data = parse_spawn_bunch(data, class_hint, has_must_be_mapped_guids=has_must_be_mapped_guids, connection=self.connection)

        class_name = extract_class_name(self._actor_class_path) or "Unknown"
        for processor in self._spawn_processors:
            if processor(class_name, self._spawn_data, self.connection, data):
                break
