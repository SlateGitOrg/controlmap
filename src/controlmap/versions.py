"""Lenient dotted-version parsing for OS version strings from MDM exports.

``"14.6.1 (23G93)"`` -> ``(14, 6, 1)``; ``"10.0.19045.4529"`` -> ``(10, 0, 19045, 4529)``.
Comparison pads with zeros, so ``14.0 == 14`` and ``14.0.1 > 14``.
"""

from __future__ import annotations

import re

_LEADING = re.compile(r"^\D*(\d+(?:\.\d+)*)")


def parse_version(text: str) -> tuple[int, ...]:
    match = _LEADING.match(text.strip())
    if not match:
        raise ValueError(f"no numeric version in {text!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 as ``left`` is older than, equal to or newer than ``right``."""
    a, b = parse_version(left), parse_version(right)
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)
