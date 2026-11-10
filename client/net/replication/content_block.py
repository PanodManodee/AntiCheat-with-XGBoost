# net/replication/content_block.py
"""Content block header and payload parsing."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from net.error_reporter import report_exception, PARSE_EXCEPTIONS
from net.guid.package_map_client import PackageMapClient
from constants import (
    ENGINE_NET_VER_CURRENT,
    ENGINE_NET_VER_SUB_OBJECT_OUTER_CHAIN,
    ENGINE_NET_VER_SUB_OBJECT_DESTROY_FLAG,
)

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader


@dataclass(slots=True)
class ContentBlockHeader:
    has_rep_layout: bool = False
    is_actor: bool = False
    object_guid: int = 0
    class_guid: int = 0
    is_deleted: bool = False
    bits_read: int = 0


@dataclass(slots=True)
class ContentBlockPayload:
    header: ContentBlockHeader
    payload_bits: int = 0
    payload_data: bytes = b""

    @property
    def has_payload(self) -> bool:
        return self.payload_bits > 0 and len(self.payload_data) > 0


def _read_header(
    reader: 'FBitReader',
    engine_ver: int = ENGINE_NET_VER_CURRENT,
) -> Optional[ContentBlockHeader]:
    """ReadContentBlockHeader — version-aware.

    v30+ (SubObjectDestroyFlag): 1-bit bIsDestroyMessage + ESubObjectDeleteFlag byte.
    v18+ (SubObjectOuterChain):  1-bit bActorIsOuter + optional outer object reference.
    Older: no destroy flag, actor is always outer.
    """
    if reader.get_bits_left() < 2:
        return None

    start_pos = reader.get_pos_bits()
    header = ContentBlockHeader()

    header.has_rep_layout = reader.read_bit()
    header.is_actor = reader.read_bit()

    if header.is_actor:
        header.bits_read = reader.get_pos_bits() - start_pos
        return header

    if reader.get_bits_left() < 8:
        reader.set_pos_bits(start_pos)
        return None

    try:
        header.object_guid = PackageMapClient.InternalLoadObject(reader, False) or 0
    except PARSE_EXCEPTIONS as exc:
        reader.set_pos_bits(start_pos)
        report_exception(f"content_block.header.guid: {exc}")
        return None

    if reader.at_end():
        reader.set_pos_bits(start_pos)
        return None

    try:
        b_stably_named = reader.read_bit()

        if not b_stably_named:
            # v30+: check for destroy message before class serialization
            if engine_ver >= ENGINE_NET_VER_SUB_OBJECT_DESTROY_FLAG:
                b_is_destroy = reader.read_bit()
                if b_is_destroy:
                    reader.serialize(1)  # ESubObjectDeleteFlag byte
                    header.is_deleted = True
                    header.bits_read = reader.get_pos_bits() - start_pos
                    return header

            # Serialize class
            header.class_guid = PackageMapClient.InternalLoadObject(reader, False) or 0

            if header.class_guid == 0:
                header.is_deleted = True
            else:
                # v18+: subobject outer chain
                if engine_ver >= ENGINE_NET_VER_SUB_OBJECT_OUTER_CHAIN:
                    b_actor_is_outer = reader.read_bit()
                    if not b_actor_is_outer:
                        PackageMapClient.InternalLoadObject(reader, False)
    except PARSE_EXCEPTIONS as exc:
        reader.set_pos_bits(start_pos)
        report_exception(f"content_block.header.subobject: {exc}")
        return None

    header.bits_read = reader.get_pos_bits() - start_pos
    return header


def _read_block(
    reader: 'FBitReader',
    engine_ver: int = ENGINE_NET_VER_CURRENT,
) -> Optional[ContentBlockPayload]:
    header = _read_header(reader, engine_ver)
    if header is None:
        return None

    if header.is_deleted:
        return ContentBlockPayload(header=header)

    if reader.get_bits_left() < 8:
        return None

    try:
        payload_bits = reader.read_uint32_packed()
    except PARSE_EXCEPTIONS as exc:
        report_exception(f"content_block.payload_bits: {exc}")
        return None

    payload = ContentBlockPayload(header=header, payload_bits=payload_bits)

    if payload_bits > 0:
        if reader.get_bits_left() < payload_bits:
            return None
        try:
            payload.payload_data = reader.serialize_bits(payload_bits)
        except PARSE_EXCEPTIONS as exc:
            report_exception(f"content_block.payload_data: {exc}")
            return None

    return payload


def iter_content_blocks(
    reader: 'FBitReader',
    engine_ver: int = ENGINE_NET_VER_CURRENT,
):
    while not reader.at_end() and reader.get_bits_left() >= 2:
        block = _read_block(reader, engine_ver)
        if block is None:
            break
        yield block
