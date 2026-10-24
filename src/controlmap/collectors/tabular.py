"""Shared helpers for CSV exports (IdP users, HR roster, endpoint inventory)."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from ..errors import CollectorError, ControlmapError
from ..settings import Settings
from ..timeutil import optional_date
from .base import read_text

_TRUE = {"true", "yes", "y", "1", "enabled", "on", "encrypted"}
_FALSE = {"false", "no", "n", "0", "disabled", "off", "", "none", "unencrypted"}
_SPLIT = re.compile(r"[;|]")


@dataclass(frozen=True)
class Row:
    line: int
    values: Mapping[str, str]

    def get(self, field: str) -> str:
        return self.values.get(field, "").strip()

    def fail(self, field: str, problem: str) -> CollectorError:
        return CollectorError(f"line {self.line}, column {field}: {problem}")

    def as_bool(self, field: str) -> bool:
        text = self.get(field).lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
        raise self.fail(field, f"not a boolean: {self.get(field)!r}")

    def as_date(self, field: str) -> date | None:
        try:
            return optional_date(self.get(field), field=field)
        except ControlmapError as exc:
            raise self.fail(field, str(exc)) from exc

    def as_int(self, field: str) -> int | None:
        text = self.get(field)
        if not text:
            return None
        try:
            return int(text)
        except ValueError as exc:
            raise self.fail(field, f"not an integer: {text!r}") from exc

    def as_list(self, field: str) -> list[str]:
        return sorted({part.strip() for part in _SPLIT.split(self.get(field)) if part.strip()})


def column_map(
    settings: Settings, presets: Mapping[str, Mapping[str, str]], default_preset: str
) -> dict[str, str]:
    """Merge a named preset with per-field ``columns:`` overrides from the config."""
    preset_name = settings.text("preset", default_preset)
    if preset_name not in presets:
        raise CollectorError(
            f"{settings.where}.preset: unknown preset {preset_name!r} "
            f"(known: {', '.join(sorted(presets))})"
        )
    mapping = dict(presets[preset_name])
    overrides = settings.mapping("columns")
    overrides.reject_unknown(frozenset(mapping))
    for field in overrides.data:
        mapping[field] = overrides.text(field)
    return mapping


def read_rows(path: Path, columns: Mapping[str, str], required: set[str]) -> list[Row]:
    """Read a CSV file and rename headers to normalized field names.

    ``columns`` maps normalized field -> header in the file. Missing required headers are an
    error; missing optional headers yield empty strings.
    """
    text = read_text(path)
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip() for h in reader.fieldnames or []]
    if not headers:
        raise CollectorError(f"{path}: empty CSV (no header row)")
    missing = sorted(field for field in required if columns[field] not in headers)
    if missing:
        wanted = ", ".join(f"{columns[f]!r} ({f})" for f in missing)
        raise CollectorError(f"{path}: missing required column(s) {wanted}")
    rows = []
    try:
        for record in reader:
            normalized = {field: (record.get(header) or "") for field, header in columns.items()}
            if not any(value.strip() for value in normalized.values()):
                continue
            rows.append(Row(reader.line_num, normalized))
    except csv.Error as exc:
        raise CollectorError(f"{path}: malformed CSV at line {reader.line_num}: {exc}") from exc
    return rows


def wrap_row_errors(path: Path, error: CollectorError) -> CollectorError:
    return CollectorError(f"{path}: {error}")
