# net/guid/static_field_mapping.py
"""Static field mapping loaded from class_net_cache.json.

Provides class max values for SerializeInt, per-class field index resolution, and detection.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

_JSON_PATH = Path(__file__).parent / "data" / "class_net_cache.json"


def _load_json() -> dict:
    try:
        return json.loads(_JSON_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _parse_max_values(raw: dict) -> dict[str, int]:
    return {
        name: info["max"]
        for name, info in raw.get("classes", {}).items()
        if isinstance(info.get("max"), int) and info["max"] > 0
    }


def _parse_per_class(raw: dict) -> dict[str, dict[int, str]]:
    """Build class_name -> {field_index -> field_name} mapping."""
    result: dict[str, dict[int, str]] = {}
    for class_name, info in raw.get("classes", {}).items():
        index_map: dict[int, str] = {}
        for i, field in enumerate(info.get("fields", [])):
            name = field.get("name")
            if name:
                index_map[i] = name
        if index_map:
            result[class_name] = index_map
    return result


_RAW = _load_json()
CLASS_MAX_VALUES: dict[str, int] = _parse_max_values(_RAW)
_PER_CLASS_FIELDS: dict[str, dict[int, str]] = _parse_per_class(_RAW)
del _RAW

def get_class_max(class_name: str) -> Optional[int]:
    return CLASS_MAX_VALUES.get(class_name)


def has_class_max(class_name: str) -> bool:
    return class_name in CLASS_MAX_VALUES


def get_field_name(class_name: str, field_index: int) -> Optional[str]:
    fields = _PER_CLASS_FIELDS.get(class_name)
    if fields:
        return fields.get(field_index)
    return None