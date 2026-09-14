# net/error_reporter.py
"""Shared exception reporting helpers."""
from __future__ import annotations

import sys
import traceback


PARSE_EXCEPTIONS = (RuntimeError, ValueError, UnicodeDecodeError)


def report_exception(context: str | None = None) -> None:
    if context:
        print(f"[ERROR] {context}")
    if sys.exc_info()[0] is not None:
        traceback.print_exc()
