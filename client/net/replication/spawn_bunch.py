# net/replication/spawn_bunch.py
"""Spawn bunch parsing (ReceivedBunch → SerializeNewActor)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from net.types import FVector, FRotator
from net.net_serialization import (
    read_network_guid,
    read_spawn_quantized_vector,
    read_rotation_compressed_short,
)
from net.guid.package_map_client import PackageMapClient
from net.replication.content_block import ContentBlockPayload, iter_content_blocks
from net.replication.rep_layout import RepLayout, RepLayoutRegistry, RepLayoutResult
from net.error_reporter import report_exception, PARSE_EXCEPTIONS
from serialization.bit_reader import FBitReader
from constants import ENGINE_NET_VER_CURRENT


@dataclass(slots=True)
class SpawnBunchHeader:
    num_guids: int = 0
    guids: list[int] = field(default_factory=list)
    header_bits: int = 0


@dataclass(slots=True)
class SerializeNewActorData:
    actor_guid: int = 0
    archetype_guid: int = 0
    level_guid: int = 0
    location: Optional[FVector] = None
    rotation: Optional[FRotator] = None
    scale: Optional[FVector] = None
    velocity: Optional[FVector] = None


@dataclass
class SpawnBunchData:
    header: SpawnBunchHeader = field(default_factory=SpawnBunchHeader)
    new_actor: SerializeNewActorData = field(default_factory=SerializeNewActorData)
    rep_layout_result: Optional[RepLayoutResult] = None
    content_blocks: list[ContentBlockPayload] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    class_name: Optional[str] = None
    raw_data: bytes = b""


class SpawnBunchParser:
    """ReceivedBunch → ProcessBunch → SerializeNewActor"""

    def __init__(self, class_name: Optional[str] = None, engine_ver: int = ENGINE_NET_VER_CURRENT, connection: Any = None) -> None:
        self._class_name = class_name
        self._engine_ver = engine_ver
        self._connection = connection
        self._rep_layout: Optional[RepLayout] = None
        if class_name:
            self._rep_layout = RepLayoutRegistry.get(class_name)

    def parse(self, data: bytes, has_must_be_mapped_guids: bool = False) -> SpawnBunchData:
        result = SpawnBunchData(raw_data=data, class_name=self._class_name)
        if len(data) < 4:
            return result

        reader = FBitReader(data, len(data) * 8)

        if has_must_be_mapped_guids:
            result.header = self._parse_header(reader)
        if reader.at_end():
            return result

        result.new_actor = self._parse_new_actor(reader)
        if reader.at_end():
            return result

        result.content_blocks = list(iter_content_blocks(reader, self._engine_ver))
        result.rep_layout_result = self._process_rep_layout(result.content_blocks)
        if result.rep_layout_result:
            result.properties.update(result.rep_layout_result.properties)

        return result

    def _parse_header(self, reader: FBitReader) -> SpawnBunchHeader:
        """uint16 NumMustBeMappedGUIDs + packed_uint64[] GUIDs"""
        header = SpawnBunchHeader()
        start_pos = reader.get_pos_bits()
        try:
            header.num_guids = reader.read_uint16()
            for _ in range(header.num_guids):
                header.guids.append(read_network_guid(reader))
        except PARSE_EXCEPTIONS as exc:
            report_exception(f"spawn.header: {exc}")
        header.header_bits = reader.get_pos_bits() - start_pos
        return header

    def _parse_new_actor(self, reader: FBitReader) -> SerializeNewActorData:
        """SerializeNewActor: Actor/Archetype/Level GUIDs + Transform"""
        data = SerializeNewActorData()
        try:
            data.actor_guid = PackageMapClient.InternalLoadObject(reader, False) or 0

            # Dynamic actor: LSB == 0
            if data.actor_guid != 0 and (data.actor_guid & 1) == 0:
                data.archetype_guid = PackageMapClient.InternalLoadObject(reader, False) or 0
                data.level_guid = PackageMapClient.InternalLoadObject(reader, False) or 0
                data.location = read_spawn_quantized_vector(reader, self._engine_ver)
                data.rotation = self._read_rotation(reader)
                data.scale = read_spawn_quantized_vector(reader, self._engine_ver)
                data.velocity = read_spawn_quantized_vector(reader, self._engine_ver)

        except PARSE_EXCEPTIONS as e:
            report_exception(f"spawn.new_actor: {e}")

        return data

    @staticmethod
    def _read_rotation(reader: FBitReader) -> Optional[FRotator]:
        """bSerializeRotation(1 bit) → SerializeCompressedShort"""
        if reader.get_bits_left() < 1:
            return None
        if not reader.read_bit():  # bSerializeRotation
            return FRotator(0.0, 0.0, 0.0)
        return read_rotation_compressed_short(reader)

    def _process_rep_layout(self, blocks: list[ContentBlockPayload]) -> Optional[RepLayoutResult]:
        if not self._rep_layout:
            return None

        combined = RepLayoutResult()
        for block in blocks:
            if not block.has_payload or not block.header.is_actor or not block.header.has_rep_layout:
                continue
            try:
                r = self._rep_layout.receive_properties(FBitReader(block.payload_data, block.payload_bits), self._connection)
                if r.success:
                    combined.properties.update(r.properties)
                    combined.handles_processed.extend(r.handles_processed)
            except PARSE_EXCEPTIONS as exc:
                report_exception(f"spawn.rep_layout: {exc}")
                continue

        return combined if combined.properties else None


def parse_spawn_bunch(data: bytes, class_name: Optional[str] = None, has_must_be_mapped_guids: bool = False, engine_ver: int = ENGINE_NET_VER_CURRENT, connection: Any = None) -> SpawnBunchData:
    return SpawnBunchParser(class_name, engine_ver, connection).parse(data, has_must_be_mapped_guids=has_must_be_mapped_guids)
