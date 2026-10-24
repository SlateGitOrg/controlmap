"""HR roster exports (CSV): who is employed, who left and when, training completion.

Evidence kind ``hris.roster`` (subject ``hris:<name>``). The roster is the source of truth
for joiner/leaver cross-checks against the IdP and the endpoint inventory.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..errors import CollectorError
from ..model import Evidence
from ..settings import Settings
from .base import Collector, CollectorContext, register_collector
from .tabular import Row, column_map, read_rows, wrap_row_errors

FIELDS = (
    "employee_id",
    "email",
    "status",
    "start_date",
    "termination_date",
    "department",
    "manager_email",
    "training_completed_on",
)
REQUIRED = {"employee_id", "email", "status", "start_date"}
PRESETS = {"generic": {field: field for field in FIELDS}}
STATUSES = {"active", "leave", "terminated"}


def normalize_employee(row: Row) -> dict[str, Any]:
    status = row.get("status").lower()
    if status not in STATUSES:
        raise row.fail("status", f"must be one of {sorted(STATUSES)}, got {status!r}")
    termination = row.as_date("termination_date")
    if status == "terminated" and termination is None:
        raise row.fail("termination_date", "required for terminated employees")
    start = row.as_date("start_date")
    if termination is not None and start is not None and termination < start:
        raise row.fail("termination_date", "is before start_date")
    return {
        "employee_id": row.get("employee_id"),
        "email": row.get("email").lower(),
        "status": status,
        "start_date": start,
        "termination_date": termination,
        "department": row.get("department") or None,
        "manager_email": row.get("manager_email").lower() or None,
        "training_completed_on": row.as_date("training_completed_on"),
    }


@register_collector
class HrisCsvCollector(Collector):
    type_name: ClassVar[str] = "hris_csv"
    description: ClassVar[str] = "HR roster export (CSV)"
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"path", "preset", "columns"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.path = settings.path("path")
        self.columns = column_map(settings, PRESETS, "generic")

    def collect(self) -> list[Evidence]:
        employees = []
        seen: set[str] = set()
        for row in read_rows(self.path, self.columns, REQUIRED):
            try:
                employee = normalize_employee(row)
            except CollectorError as exc:
                raise wrap_row_errors(self.path, exc) from exc
            if employee["employee_id"] in seen:
                raise CollectorError(
                    f"{self.path}: line {row.line}: duplicate employee_id {employee['employee_id']}"
                )
            seen.add(employee["employee_id"])
            employees.append(employee)
        data = {"employees": sorted(employees, key=lambda e: (e["email"], e["employee_id"]))}
        return [
            self.evidence(
                "hris.roster",
                f"hris:{self.name}",
                data,
                self.relpath(self.path),
                self.collected_at(),
            )
        ]
