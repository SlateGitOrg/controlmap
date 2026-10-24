"""SOC 2 TSC <-> ISO/IEC 27001:2022 Annex A crosswalk derived from the control library.

The crosswalk is not a separate hand-maintained table: a TSC criterion and an Annex A
control are linked when at least one company control is mapped to both. That keeps the
crosswalk consistent with what is actually tested, and makes gaps visible: in-scope criteria
with no control, and Annex A controls nothing maps to.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Any

from .frameworks import iso_sort_key, tsc_sort_key
from .library import Library
from .model import EvaluationRun, Status


@dataclass(frozen=True)
class CriterionRow:
    id: str
    label: str
    category: str
    controls: tuple[str, ...]
    iso: tuple[str, ...]
    status: Status | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category,
            "controls": list(self.controls),
            "iso27001": list(self.iso),
            "status": self.status.value if self.status else None,
        }


@dataclass(frozen=True)
class IsoRow:
    id: str
    title: str
    theme: str
    controls: tuple[str, ...]
    tsc: tuple[str, ...]
    status: Status | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "theme": self.theme,
            "controls": list(self.controls),
            "tsc": list(self.tsc),
            "status": self.status.value if self.status else None,
        }


@dataclass(frozen=True)
class Crosswalk:
    criteria: tuple[CriterionRow, ...]
    iso: tuple[IsoRow, ...]

    @property
    def tsc_gaps(self) -> list[str]:
        return [row.id for row in self.criteria if not row.controls]

    @property
    def iso_unmapped(self) -> list[str]:
        return [row.id for row in self.iso if not row.controls]

    def coverage(self) -> dict[str, Any]:
        covered = len(self.criteria) - len(self.tsc_gaps)
        iso_covered = len(self.iso) - len(self.iso_unmapped)
        return {
            "tsc_in_scope": len(self.criteria),
            "tsc_covered": covered,
            "tsc_gaps": self.tsc_gaps,
            "iso_total": len(self.iso),
            "iso_covered": iso_covered,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": self.coverage(),
            "criteria": [row.to_dict() for row in self.criteria],
            "iso27001": [row.to_dict() for row in self.iso],
        }

    def to_csv(self) -> str:
        """One row per (criterion, control, Annex A control) triple, for spreadsheets."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["tsc_criterion", "tsc_label", "control", "iso27001_annex_a", "status"])
        for row in self.criteria:
            if not row.controls:
                writer.writerow([row.id, row.label, "", "", "GAP"])
                continue
            for control in row.controls:
                writer.writerow([row.id, row.label, control, " ".join(row.iso), row.status or ""])
        return buffer.getvalue()


def build_crosswalk(library: Library, run: EvaluationRun | None = None) -> Crosswalk:
    statuses: dict[str, Status] = {}
    if run is not None:
        statuses = {c.control_id: c.status for c in run.controls}
    in_scope = library.catalogs.tsc_in_scope(list(library.tsc_categories))
    criteria = []
    for criterion in sorted(in_scope, key=lambda c: tsc_sort_key(c.id)):
        controls = [c for c in library.controls if criterion.id in c.tsc]
        iso = sorted({i for c in controls for i in c.iso}, key=iso_sort_key)
        criteria.append(
            CriterionRow(
                criterion.id,
                criterion.label,
                criterion.category,
                tuple(c.id for c in controls),
                tuple(iso),
                _rollup([statuses[c.id] for c in controls if c.id in statuses], run),
            )
        )
    iso_rows = []
    for iso_control in sorted(library.catalogs.iso.values(), key=lambda c: iso_sort_key(c.id)):
        controls = [c for c in library.controls if iso_control.id in c.iso]
        tsc = sorted({t for c in controls for t in c.tsc}, key=tsc_sort_key)
        iso_rows.append(
            IsoRow(
                iso_control.id,
                iso_control.title,
                iso_control.theme,
                tuple(c.id for c in controls),
                tuple(tsc),
                _rollup([statuses[c.id] for c in controls if c.id in statuses], run),
            )
        )
    return Crosswalk(tuple(criteria), tuple(iso_rows))


def _rollup(statuses: list[Status], run: EvaluationRun | None) -> Status | None:
    if run is None or not statuses:
        return None
    return Status.worst(statuses)
