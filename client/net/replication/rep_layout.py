# net/replication/rep_layout.py
"""RepLayout property receive and registry"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

from net.replication.types import (
    PropertyType,
    PropertyDef,
    RepLayoutTemplate,
)
from net.net_serialization import (
    read_quantized_vector,
    read_vector_double,
    read_rotation_short,
    read_network_guid,
    read_fname,
)
from constants import ENABLE_PROPERTY_CHECKSUMS
from net.error_reporter import report_exception, PARSE_EXCEPTIONS
from net.replication.templates import ALL_TEMPLATES
from net.replication.rep_handle_map import build_property_defs, get_total_handles

if TYPE_CHECKING:
    from serialization.bit_reader import FBitReader


_READERS: dict[PropertyType, Callable] = {
    PropertyType.BOOL:          lambda r, _: r.read_bit(),
    PropertyType.BYTE:          lambda r, _: r.read_byte(),
    PropertyType.INT:           lambda r, _: r.read_int32(),
    PropertyType.FLOAT:         lambda r, _: r.read_float(),
    PropertyType.DOUBLE:        lambda r, _: r.read_double(),
    PropertyType.INT8:          lambda r, _: r.read_int8(),
    PropertyType.INT16:         lambda r, _: r.read_int16(),
    PropertyType.INT64:         lambda r, _: struct.unpack('<q', r.serialize_bits(64))[0],
    PropertyType.UINT16:        lambda r, _: r.read_uint16(),
    PropertyType.UINT32:        lambda r, _: r.read_uint32(),
    PropertyType.UINT64:        lambda r, _: r.read_uint64(),
    PropertyType.VECTOR:        lambda r, _: read_quantized_vector(r),
    PropertyType.VECTOR_DOUBLE: lambda r, _: read_vector_double(r),
    PropertyType.ROTATOR:       lambda r, _: read_rotation_short(r),
    PropertyType.STRING:        lambda r, _: r.read_fstring(),
    PropertyType.OBJECT:        lambda r, _: read_network_guid(r),
    PropertyType.SOFT_OBJECT:   lambda r, _: read_network_guid(r),
    PropertyType.WEAK_OBJECT:   lambda r, _: read_network_guid(r),
    PropertyType.INTERFACE:     lambda r, _: read_network_guid(r),
    PropertyType.CLASS:         lambda r, _: read_network_guid(r),
    PropertyType.NAME:          lambda r, _: read_fname(r),
}


@dataclass
class RepLayoutResult:
    properties: dict[str, Any] = field(default_factory=dict)
    handles_processed: list[int] = field(default_factory=list)
    success: bool = True


class RepLayout:
    def __init__(self, class_name: str, properties: list[PropertyDef],
                 total_handles: int = 0,
                 on_update: Optional[Callable] = None) -> None:
        self._class_name = class_name
        self._properties = properties
        self._total_handles = total_handles or max((p.handle for p in properties), default=0)
        self._on_update = on_update
        self._handle_to_prop: dict[int, PropertyDef] = {
            p.handle: p for p in properties
        }

    @property
    def class_name(self) -> str:
        return self._class_name

    def receive_properties(self, reader: 'FBitReader', context: Any = None) -> RepLayoutResult:
        """Read replicated properties from the bitstream"""
        result = RepLayoutResult()
        raw_buffer = reader.get_buffer()
        checksum = False
        trace: list[str] = []

        try:
            checksum = reader.read_bit() if ENABLE_PROPERTY_CHECKSUMS else False

            pos_before = reader.get_pos_bits()
            handle = reader.read_uint32_packed()
            if checksum:
                reader.serialize_bits(32)
            trace.append(f"  @{pos_before}: handle={handle}")

            while handle != 0:
                result.handles_processed.append(handle)

                prop = self._handle_to_prop.get(handle)
                if prop is None:
                    report_exception(f"RepLayout({self.class_name}) unknown handle {handle} after {result.handles_processed[:-1]}, pos={reader.get_pos_bits()}/{reader.get_num_bits()}")
                    result.success = False
                    break

                pos_before = reader.get_pos_bits()
                value = self._read_property(reader, prop, context, checksum)
                pos_after = reader.get_pos_bits()
                trace.append(f"  @{pos_before}-{pos_after}: h{handle} {prop.name}({prop.prop_type.name}) = {value!r}")

                if value is None:
                    if not prop.serializer:
                        report_exception(
                            f"RepLayout({self.class_name}) no reader for handle {handle} ({prop.name}, {prop.prop_type.name}), pos={reader.get_pos_bits()}/{reader.get_num_bits()}")
                    result.success = False
                    break

                if checksum and prop.prop_type != PropertyType.DYNAMIC_ARRAY:
                    reader.serialize_bits(32)

                result.properties[prop.name] = value

                if reader.at_end():
                    break

                pos_before = reader.get_pos_bits()
                handle = reader.read_uint32_packed()
                if checksum:
                    reader.serialize_bits(32)
                trace.append(f"  @{pos_before}: handle={handle}")

        except PARSE_EXCEPTIONS:
            result.success = False
            report_exception(f"RepLayout({self.class_name}) receive_properties failed")

        if not result.success:
            total_bytes = (reader.get_num_bits() + 7) // 8
            hex_dump = raw_buffer[:total_bytes].hex(' ')
            trace_str = '\n'.join(trace)
            print(f"[REPLAYOUT-DUMP] {self.class_name} checksum={checksum} handles={result.handles_processed} pos={reader.get_pos_bits()}/{reader.get_num_bits()}\n{trace_str}\n  hex({total_bytes}): {hex_dump}")

        if result.success and result.properties:
            print(f"[REPLAYOUT] {self.class_name} OK handles={result.handles_processed} props={{{', '.join(f'{k}={v!r}' for k, v in result.properties.items())}}} bits={reader.get_pos_bits()}/{reader.get_num_bits()}")
        elif not result.success and result.properties:
            print(f"[REPLAYOUT] {self.class_name} PARTIAL handles={result.handles_processed} props={{{', '.join(f'{k}={v!r}' for k, v in result.properties.items())}}} bits={reader.get_pos_bits()}/{reader.get_num_bits()}")
        elif result.handles_processed:
            print(f"[REPLAYOUT] {self.class_name} EMPTY handles={result.handles_processed} bits={reader.get_pos_bits()}/{reader.get_num_bits()} success={result.success}")

        if result.properties and self._on_update:
            self._on_update(result.properties, context)

        return result

    def _read_property(self, reader: 'FBitReader', prop: PropertyDef, ctx: Any, checksum: bool = False) -> Any:
        if prop.prop_type == PropertyType.DYNAMIC_ARRAY:
            return self._read_dynamic_array(reader, prop, ctx, checksum)
        if prop.serializer is not None:
            return prop.serializer(reader, ctx)
        fn = _READERS.get(prop.prop_type)
        if fn is not None:
            return fn(reader, ctx)
        return None

    def _read_dynamic_array(self, reader: 'FBitReader', prop: PropertyDef, ctx: Any, checksum: bool = False) -> Any:
        """ReceiveProperties_r dynamic array path"""
        array_num = reader.read_uint16()

        read_handle = reader.read_uint32_packed()
        if checksum:
            reader.serialize_bits(32)

        if read_handle == 0:
            return []

        if not prop.inner_defs:
            report_exception(f"DynArray({prop.name}) ArrayNum={array_num} SubHandle={read_handle} but no inner_defs, cannot parse")
            return None

        sorted_inners = sorted(prop.inner_defs, key=lambda p: p.handle)
        elements = []
        current_handle = 0

        for elem_idx in range(array_num):
            elem_data = {}

            for inner_prop in sorted_inners:
                current_handle += 1

                if current_handle == read_handle:
                    if inner_prop.prop_type == PropertyType.DYNAMIC_ARRAY:
                        value = self._read_dynamic_array(reader, inner_prop, ctx, checksum)
                    else:
                        value = self._read_property(reader, inner_prop, ctx, checksum)

                    if value is None:
                        report_exception(f"DynArray({prop.name})[{elem_idx}] failed reading inner handle {read_handle} ({inner_prop.name})")
                        return None

                    if checksum and inner_prop.prop_type != PropertyType.DYNAMIC_ARRAY:
                        reader.serialize_bits(32)

                    elem_data[inner_prop.name] = value

                    read_handle = reader.read_uint32_packed()
                    if checksum:
                        reader.serialize_bits(32)

                    if read_handle == 0:
                        break

            elements.append(elem_data)

            if read_handle == 0:
                for _ in range(elem_idx + 1, array_num):
                    elements.append({})
                break

        return elements


class RepLayoutRegistry:
    _templates: list[RepLayoutTemplate] = []
    _instances: dict[str, RepLayout] = {}

    @classmethod
    def register_templates(cls, templates: list[RepLayoutTemplate]) -> None:
        cls._templates.extend(templates)

    @classmethod
    def _find_template(cls, class_name: str) -> Optional[RepLayoutTemplate]:
        for t in cls._templates:
            if t.match and t.match(class_name):
                return t
        return None

    @classmethod
    def get(cls, class_name: str) -> Optional[RepLayout]:
        if class_name in cls._instances:
            return cls._instances[class_name]

        try:
            defs = build_property_defs(class_name)
        except KeyError:
            defs = None

        if defs is None:
            return None

        total_handles = get_total_handles(class_name)
        template = cls._find_template(class_name)
        on_update = template.on_update if template else None
        layout = RepLayout(class_name, defs, total_handles=total_handles, on_update=on_update)
        cls._instances[class_name] = layout
        defined = len(layout._handle_to_prop)
        print(f"[REPLAYOUT] Auto-registered {class_name} ({defined} defs, {total_handles} total handles)")
        return layout


RepLayoutRegistry.register_templates(ALL_TEMPLATES)