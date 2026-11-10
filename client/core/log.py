# core/log.py
"""Simple file-append logger."""
from __future__ import annotations

from datetime import datetime


def append_log(filename: str, message: str) -> None:
    try:
        with open(filename, "a", encoding="utf-8") as file:
            file.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}\n")
    except OSError:
        pass
