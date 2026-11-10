# net/types.py
"""Common network data types (vectors, rotators)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True, frozen=True)
class FVector:
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

    def __repr__(self) -> str:
        return f"FVector({self.x:.2f}, {self.y:.2f}, {self.z:.2f})"


@dataclass(slots=True, frozen=True)
class FRotator:
    pitch: float = 0.0
    yaw: float = 0.0
    roll: float = 0.0

    def __repr__(self) -> str:
        return f"FRotator({self.pitch:.2f}, {self.yaw:.2f}, {self.roll:.2f})"


def extract_class_name(class_path: str | None) -> str | None:
    """Extract class name from a UE5 class path"""
    if not class_path:
        return None
    if "." in class_path:
        return class_path.rsplit(".", 1)[-1]
    if "/" in class_path:
        return class_path.rsplit("/", 1)[-1]
    return class_path