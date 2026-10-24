"""Canonical JSON encoding and hashing.

Evidence digests and package manifests must be byte-for-byte reproducible, so every hashed
JSON document goes through :func:`canonical_json`: sorted keys, no insignificant whitespace,
UTF-8, and dates rendered as ISO-8601 strings.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .timeutil import isoformat

_CHUNK = 1 << 16


def to_jsonable(value: Any) -> Any:
    """Convert dates, tuples, sets and mappings into plain JSON-compatible values."""
    if isinstance(value, datetime):
        return isoformat(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(to_jsonable(v) for v in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"value of type {type(value).__name__} is not JSON-serialisable")


def canonical_json(value: Any) -> bytes:
    """Encode ``value`` as canonical UTF-8 JSON bytes."""
    return json.dumps(
        to_jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def pretty_json(value: Any) -> str:
    """Human-readable but still deterministic JSON (sorted keys, 2-space indent, final newline)."""
    return (
        json.dumps(
            to_jsonable(value), sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False
        )
        + "\n"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    """Return ``(hex digest, size in bytes)`` for a file, streaming it in 64 KiB chunks."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
