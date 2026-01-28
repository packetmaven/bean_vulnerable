"""
Safe JSON helpers.

Python's built-in json encoder raises:
  ValueError: Circular reference detected
when it encounters cyclic container graphs. This module provides a small
sanitizer that breaks cycles and converts non-JSON-native types into strings.
"""

from __future__ import annotations

import json
from typing import Any, Optional, Set, TextIO


def sanitize_for_json(obj: Any, seen: Optional[Set[int]] = None, depth: int = 0, max_depth: int = 50) -> Any:
    """
    Recursively sanitize objects for JSON encoding, breaking circular references.

    Returns only JSON-native types (dict/list/str/bool/int/float/None) and uses
    placeholder strings for cycles and depth limits.
    """
    if seen is None:
        seen = set()

    obj_id = id(obj)
    if obj_id in seen:
        return "[circular_reference]"
    if depth > max_depth:
        return "[max_depth_exceeded]"

    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, (list, tuple)):
        seen.add(obj_id)
        try:
            return [sanitize_for_json(item, seen, depth + 1, max_depth) for item in obj]
        finally:
            seen.discard(obj_id)

    if isinstance(obj, dict):
        seen.add(obj_id)
        try:
            # Force keys to strings to ensure JSON encodability.
            return {
                str(k): sanitize_for_json(v, seen, depth + 1, max_depth)
                for k, v in obj.items()
            }
        finally:
            seen.discard(obj_id)

    if hasattr(obj, "__dict__") and not isinstance(obj, (type, type(lambda: None))):
        seen.add(obj_id)
        try:
            return {
                str(k): sanitize_for_json(v, seen, depth + 1, max_depth)
                for k, v in obj.__dict__.items()
                if not str(k).startswith("_")
            }
        finally:
            seen.discard(obj_id)

    return str(obj)


def safe_json_dumps(obj: Any, indent: int = 2, **kwargs: Any) -> str:
    """Safely serialize objects to JSON by breaking circular references."""
    sanitized = sanitize_for_json(obj)
    return json.dumps(sanitized, indent=indent, **kwargs)


def safe_json_dump(obj: Any, fp: TextIO, indent: int = 2, **kwargs: Any) -> None:
    """Safely write JSON to an open file-like object."""
    fp.write(safe_json_dumps(obj, indent=indent, **kwargs))
    fp.write("\n")

