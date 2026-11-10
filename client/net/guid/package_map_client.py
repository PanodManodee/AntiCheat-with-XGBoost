# net/guid/package_map_client.py
"""PackageMapClient for object serialization and NetFieldExport handling."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Optional, TYPE_CHECKING, Iterator

from serialization.bit_reader import FBitReader
from net.guid.net_field_export import FNetFieldExport, FNetFieldExportGroup, NetFieldExportManager
from net.guid.static_field_mapping import get_class_max
from net.net_serialization import read_fname, read_network_guid
from net.types import extract_class_name

if TYPE_CHECKING:
    from net.connection import NetConnection


class ExportFlags(IntFlag):
    None_ = 0
    bHasPath = 1
    bNoLoad = 2
    bHasNetworkChecksum = 4
    All = 7


@dataclass(slots=True)
class NetGUIDEntry:
    net_guid: int = 0
    path_name: str = ""
    outer_guid: int = 0
    network_checksum: int = 0
    is_default_object: bool = False


class NetGUIDCache:
    __slots__ = ('guid_to_entry', 'path_to_guid')

    def __init__(self):
        self.guid_to_entry: dict[int, NetGUIDEntry] = {}
        self.path_to_guid: dict[str, int] = {}

    def register_guid(self, net_guid: int, path_name: str, outer_guid: int = 0,
                      network_checksum: int = 0) -> None:
        if net_guid == 0:
            return

        entry = NetGUIDEntry(
            net_guid=net_guid,
            path_name=path_name,
            outer_guid=outer_guid,
            network_checksum=network_checksum,
            is_default_object=(net_guid == 1)
        )
        self.guid_to_entry[net_guid] = entry
        if path_name:
            self.path_to_guid[path_name] = net_guid

    def get_path(self, net_guid: int) -> Optional[str]:
        entry = self.guid_to_entry.get(net_guid)
        return entry.path_name if entry else None

    def get_guid(self, path_name: str) -> Optional[int]:
        return self.path_to_guid.get(path_name)

    def get_full_path(self, net_guid: int) -> str:
        entry = self.guid_to_entry.get(net_guid)
        if not entry:
            return ""

        if entry.outer_guid and entry.outer_guid != net_guid:
            outer_path = self.get_full_path(entry.outer_guid)
            if outer_path:
                return f"{outer_path}.{entry.path_name}"

        return entry.path_name

    def get_serialize_int_max(self, class_path: str) -> Optional[int]:
        """Get SerializeInt max value for a class path, or None if unknown."""
        class_name = extract_class_name(class_path)
        if not class_name:
            return None

        max_val = get_class_max(class_name)
        if max_val is not None:
            return max_val

        if class_name.endswith("_C"):
            max_val = get_class_max(class_name[:-2])
            if max_val is not None:
                return max_val

        if not class_name.endswith("_C"):
            max_val = get_class_max(class_name + "_C")
            if max_val is not None:
                return max_val

        return None

    def find_class_in_guid_list(self, guids: list[int]) -> Optional[str]:
        for guid in guids:
            entry = self.guid_to_entry.get(guid)
            if entry and entry.path_name:
                path = entry.path_name
                if path.startswith("/Script/") or path.startswith("/Game/"):
                    parts = path.split(".")
                    if len(parts) >= 2:
                        class_name = parts[-1]
                        if not class_name.endswith("_C") and not class_name[-1].isdigit():
                            return path
        return None


@dataclass(slots=True)
class PackageMapState:
    guid_cache: NetGUIDCache = field(default_factory=NetGUIDCache)
    field_export_manager: NetFieldExportManager = field(default_factory=NetFieldExportManager)
    current_bunch_guids: list[int] = field(default_factory=list)


_current_package_map_state: ContextVar[PackageMapState | None] = ContextVar(
    "current_package_map_state",
    default=None,
)


def create_package_map_state() -> PackageMapState:
    return PackageMapState()


def _get_active_state() -> PackageMapState:
    state = _current_package_map_state.get()
    if state is None:
        raise RuntimeError(
            "No active PackageMapState. "
            "Wrap the call site with use_package_map_state()."
        )
    return state


@contextmanager
def use_package_map_state(state: PackageMapState) -> Iterator[None]:
    token = _current_package_map_state.set(state)
    try:
        yield
    finally:
        _current_package_map_state.reset(token)


def get_net_guid_cache() -> NetGUIDCache:
    return _get_active_state().guid_cache


def reset_net_guid_cache() -> None:
    _get_active_state().guid_cache = NetGUIDCache()


def get_net_field_export_manager() -> NetFieldExportManager:
    return _get_active_state().field_export_manager


def reset_net_field_export_manager() -> None:
    _get_active_state().field_export_manager = NetFieldExportManager()


class PackageMapClient:
    @staticmethod
    def begin_bunch_guids():
        _get_active_state().current_bunch_guids = []

    @staticmethod
    def get_bunch_guids() -> list[int]:
        return _get_active_state().current_bunch_guids.copy()

    @staticmethod
    def InternalLoadObject(ar: FBitReader, isExportingNetGUIDBunch, internalLoadObjectRecursionCount: int = 0):
        if internalLoadObjectRecursionCount > 16:
            return None

        netGuid = read_network_guid(ar)
        if netGuid < 1:
            return None

        state = _get_active_state()
        cache = state.guid_cache
        outer_guid = 0
        path_name = ""
        network_checksum = 0

        if netGuid == 1 or isExportingNetGUIDBunch:
            raw_flags = ar.read_byte()
            flags = ExportFlags(raw_flags & int(ExportFlags.All))

            if flags & ExportFlags.bHasPath:
                outer_result = PackageMapClient.InternalLoadObject(
                    ar, isExportingNetGUIDBunch, internalLoadObjectRecursionCount + 1
                )
                if outer_result:
                    outer_guid = outer_result

                path_name = ar.read_fstring()

                if flags & ExportFlags.bHasNetworkChecksum:
                    network_checksum = ar.read_uint32()

                if path_name:
                    cache.register_guid(netGuid, path_name, outer_guid, network_checksum)

                state.current_bunch_guids.append(netGuid)
                return netGuid

        state.current_bunch_guids.append(netGuid)
        return netGuid

    @staticmethod
    def ReceiveNetFieldExports(ar: FBitReader):
        manager = get_net_field_export_manager()

        num_exports = ar.read_uint32_packed()

        if num_exports > 2048:
            return

        for _ in range(num_exports):
            group_index = ar.read_uint32_packed()
            was_exported = ar.read_uint32_packed()

            if was_exported:
                path_name = ar.read_fstring()
                net_field_exports_length = ar.read_uint32_packed()

                if net_field_exports_length > 4096:
                    return

                group = manager.get_group_by_index(group_index)
                if group is None:
                    group = FNetFieldExportGroup(
                        path_name=path_name,
                        path_name_index=group_index,
                        net_field_exports_length=net_field_exports_length
                    )
                    manager.add_group(group_index, group)
                else:
                    group.net_field_exports_length = max(group.net_field_exports_length, net_field_exports_length)
            else:
                group = manager.get_group_by_index(group_index)

            field_export = PackageMapClient.ReadNetFieldExport(ar)
            if field_export and field_export.is_exported and group is not None:
                group.net_field_exports[field_export.handle] = field_export

    @staticmethod
    def ReadNetFieldExport(ar: FBitReader) -> Optional[FNetFieldExport]:
        export = FNetFieldExport()

        flags = ar.read_byte()
        export.is_exported = bool(flags & 0x01)
        export.b_export_blob = bool(flags & 0x02)

        if not export.is_exported:
            return export

        export.handle = ar.read_uint32_packed()
        export.compatible_checksum = ar.read_uint32()
        export.export_name = read_fname(ar)

        if export.b_export_blob:
            # SafeNetSerializeTArray_Default<4096>:
            # CeilLogTwo(4096)+1 = 13 bits for element count
            raw = ar.serialize_bits(13)
            blob_count = int.from_bytes(raw, "little") & 0x1FFF
            if blob_count > 4096:
                blob_count = 4096
            export.blob = ar.serialize_bits(blob_count * 8) if blob_count > 0 else b""

        return export

    @staticmethod
    def ReceiveNetFieldExportsCompat(ar: FBitReader):
        manager = get_net_field_export_manager()

        num_layout_cmd_exports = ar.read_uint32()

        MAX_SERIALIZED_NET_EXPORT_GROUPS = 2048
        if num_layout_cmd_exports > MAX_SERIALIZED_NET_EXPORT_GROUPS:
            ar.set_error()
            return

        exports_read = 0
        while exports_read < num_layout_cmd_exports:
            group_index = ar.read_uint32_packed()

            b_exporting_group = ar.read_bit()

            if b_exporting_group:
                path_name = ar.read_fstring()
                num_exports_in_group = ar.read_uint32()

                group = manager.get_group_by_index(group_index)
                if group is None:
                    group = FNetFieldExportGroup(
                        path_name=path_name,
                        path_name_index=group_index,
                        net_field_exports_length=num_exports_in_group
                    )
                    manager.add_group(group_index, group)
                else:
                    group.path_name = path_name
                    group.net_field_exports_length = max(group.net_field_exports_length, num_exports_in_group)
            else:
                group = manager.get_group_by_index(group_index)
                if group is None:
                    field_export = PackageMapClient.ReadNetFieldExport(ar)
                    exports_read += 1
                    continue

            field_export = PackageMapClient.ReadNetFieldExport(ar)
            if field_export and field_export.is_exported:
                group.net_field_exports[field_export.handle] = field_export

            exports_read += 1
