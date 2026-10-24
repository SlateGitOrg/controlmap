"""Framework catalogs: SOC 2 TSC criteria and ISO/IEC 27001:2022 Annex A controls.

Only identifiers and short labels are bundled (see ``DATA.md`` for licensing notes). The
catalogs exist so that the control library can be validated: a typo such as ``CC6.9`` or
``A.8.35`` is caught at load time instead of silently producing an empty crosswalk row.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import yaml

from .errors import LibraryError

_TSC_ID = re.compile(r"^(CC[1-9]\.[1-9]|A1\.[1-9]|C1\.[1-9]|PI1\.[1-9]|P[1-8]\.[1-9])$")
_ISO_ID = re.compile(r"^[5-8]\.[1-9][0-9]?$")


@dataclass(frozen=True)
class Criterion:
    id: str
    category: str
    label: str


@dataclass(frozen=True)
class IsoControl:
    id: str
    theme: str
    title: str


@dataclass(frozen=True)
class Catalogs:
    tsc: dict[str, Criterion]
    tsc_categories: dict[str, str]
    iso: dict[str, IsoControl]
    iso_themes: dict[str, str]

    def tsc_in_scope(self, categories: list[str]) -> list[Criterion]:
        return [c for c in self.tsc.values() if c.category in categories]


def normalize_iso_id(value: str) -> str:
    """Accept ``8.5``, ``A.8.5`` and ``A8.5``; return the canonical ``8.5``."""
    text = value.strip().upper()
    if text.startswith("A."):
        text = text[2:]
    elif text.startswith("A"):
        text = text[1:]
    return text


def _load(name: str) -> Any:
    resource = files("controlmap.data").joinpath(name)
    try:
        return yaml.safe_load(resource.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - packaging error
        raise LibraryError(f"cannot load bundled catalog {name}: {exc}") from exc


def load_catalogs() -> Catalogs:
    tsc_doc = _load("tsc2017.yaml")
    iso_doc = _load("iso27001_2022.yaml")
    tsc: dict[str, Criterion] = {}
    categories = {str(k): str(v) for k, v in tsc_doc["categories"].items()}
    for entry in tsc_doc["criteria"]:
        criterion = Criterion(str(entry["id"]), str(entry["category"]), str(entry["label"]))
        if not _TSC_ID.match(criterion.id) or criterion.category not in categories:
            raise LibraryError(f"bundled TSC catalog has a bad entry: {entry}")
        tsc[criterion.id] = criterion
    iso: dict[str, IsoControl] = {}
    themes = {str(k): str(v) for k, v in iso_doc["themes"].items()}
    for entry in iso_doc["controls"]:
        control = IsoControl(str(entry["id"]), str(entry["theme"]), str(entry["title"]))
        if not _ISO_ID.match(control.id) or control.theme not in themes:
            raise LibraryError(f"bundled ISO catalog has a bad entry: {entry}")
        iso[control.id] = control
    return Catalogs(tsc, categories, iso, themes)


def iso_sort_key(control_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in control_id.split("."))


def tsc_sort_key(criterion_id: str) -> tuple[int, str, int, int]:
    prefix_order = {"CC": 0, "A": 1, "C": 2, "PI": 3, "P": 4}
    match = re.match(r"^([A-Z]+)(\d+)\.(\d+)$", criterion_id)
    if not match:
        return (9, criterion_id, 0, 0)
    prefix, major, minor = match.groups()
    return (prefix_order.get(prefix, 9), prefix, int(major), int(minor))
