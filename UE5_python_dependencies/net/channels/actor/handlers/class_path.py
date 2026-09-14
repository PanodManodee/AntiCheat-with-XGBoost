# net/channels/actor/handlers/class_path.py
"""Actor class-path resolver helpers."""
from __future__ import annotations

from collections.abc import Callable

from net.guid.static_field_mapping import has_class_max
from net.types import extract_class_name

ClassPathMatcher = Callable[[str], bool]
ClassPathTransformer = Callable[[str], str]
ClassPathRule = tuple[ClassPathMatcher, ClassPathTransformer]


def _is_default_object_path(path: str) -> bool:
    return path.startswith("Default__")


def _strip_default_prefix(path: str) -> str:
    return path[9:]


def _is_game_or_script_class_path(path: str) -> bool:
    if "/Maps/" in path:
        return False
    return path.startswith("/Game/") or (path.startswith("/Script/") and "." in path)


def _identity(path: str) -> str:
    return path


CLASS_PATH_RULES: tuple[ClassPathRule, ...] = (
    (_is_default_object_path, _strip_default_prefix),
    (_is_game_or_script_class_path, _identity),
)


def is_class_known(class_name: str | None) -> bool:
    if not class_name:
        return False
    if has_class_max(class_name):
        return True
    if class_name.endswith("_C"):
        return has_class_max(class_name[:-2])
    return has_class_max(class_name + "_C")


def resolve_actor_class_path(
    guids: list[int],
    path_lookup: Callable[[int], str | None],
) -> str | None:
    paths = [path_lookup(guid) for guid in guids]
    for matcher, transform in CLASS_PATH_RULES:
        for path in paths:
            if path and matcher(path):
                return transform(path)
    return None
