# net/guid/net_field_export.py
"""NetFieldExport classes for RPC/property name mapping."""
from __future__ import annotations

from typing import Optional
from dataclasses import dataclass, field


@dataclass(slots=True)
class FNetFieldExport:
    handle: int = 0
    compatible_checksum: int = 0
    export_name: str = ""
    is_exported: bool = False
    b_export_blob: bool = False
    blob: bytes = b""
    incompatible: bool = False


@dataclass(slots=True)
class FNetFieldExportGroup:
    path_name: str = ""
    path_name_index: int = 0
    net_field_exports_length: int = 0
    net_field_exports: dict[int, FNetFieldExport] = field(default_factory=dict)

    def get_export_name(self, field_handle: int) -> Optional[str]:
        export = self.net_field_exports.get(field_handle)
        return export.export_name if export else None


class NetFieldExportManager:
    __slots__ = ('groups_by_index', 'groups_by_path')

    def __init__(self):
        self.groups_by_index: dict[int, FNetFieldExportGroup] = {}
        self.groups_by_path: dict[str, FNetFieldExportGroup] = {}

    def add_group(self, index: int, group: FNetFieldExportGroup):
        self.groups_by_index[index] = group
        if group.path_name:
            self.groups_by_path[group.path_name] = group

    def get_group_by_index(self, index: int) -> Optional[FNetFieldExportGroup]:
        return self.groups_by_index.get(index)

    def get_group_by_path(self, path: str) -> Optional[FNetFieldExportGroup]:
        return self.groups_by_path.get(path)

    def get_export_name(self, group_index: int, field_handle: int) -> Optional[str]:
        group = self.groups_by_index.get(group_index)
        return group.get_export_name(field_handle) if group else None
