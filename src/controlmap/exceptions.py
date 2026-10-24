"""Exception (risk-acceptance) register.

An exception is a time-boxed, approved acceptance of specific deviations::

    exceptions:
      - id: EXC-2026-004
        control: NW-02
        rule: cloud.admin_ports_restricted     # optional: limit to one rule
        resources: ["sg:sg-0bastion*"]         # fnmatch patterns over finding resources
        reason: Break-glass bastion pending migration to SSM Session Manager.
        compensating_controls: [Source IP allow-list at the edge, session recording]
        risk_owner: Head of Infrastructure     # roles, not names
        approved_by: CISO
        approved_on: 2026-08-01
        expires_on: 2027-01-31

During evaluation, a finding whose control (and rule, if given) and resource match an
**active** exception is marked as excepted; it no longer fails the control, but it stays in
the package so an auditor sees both the deviation and the approval. Expired or not-yet-approved
exceptions never apply. The register report lists active, expiring-soon, expired and unused
entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .errors import ExceptionRegisterError
from .library import Library
from .model import Finding
from .settings import Settings, load_yaml

_EXC_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
ENTRY_KEYS = frozenset(
    {
        "id",
        "control",
        "rule",
        "resources",
        "reason",
        "compensating_controls",
        "risk_owner",
        "approved_by",
        "approved_on",
        "expires_on",
    }
)


class ExceptionState(StrEnum):
    PENDING = "pending"  # approved_on is after the evaluation date
    ACTIVE = "active"
    EXPIRED = "expired"


@dataclass(frozen=True)
class RiskException:
    id: str
    control: str
    rule: str | None
    resources: tuple[str, ...]
    reason: str
    compensating_controls: tuple[str, ...]
    risk_owner: str
    approved_by: str
    approved_on: date
    expires_on: date

    def state(self, as_of: date) -> ExceptionState:
        if as_of < self.approved_on:
            return ExceptionState.PENDING
        if as_of > self.expires_on:
            return ExceptionState.EXPIRED
        return ExceptionState.ACTIVE

    def covers(self, control_id: str, rule: str, finding: Finding) -> bool:
        if control_id != self.control:
            return False
        if self.rule is not None and self.rule != rule:
            return False
        return any(fnmatchcase(finding.resource, pattern) for pattern in self.resources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "control": self.control,
            "rule": self.rule,
            "resources": list(self.resources),
            "reason": self.reason,
            "compensating_controls": list(self.compensating_controls),
            "risk_owner": self.risk_owner,
            "approved_by": self.approved_by,
            "approved_on": self.approved_on.isoformat(),
            "expires_on": self.expires_on.isoformat(),
        }


class ExceptionRegister:
    """The validated, immutable set of exceptions."""

    def __init__(self, entries: list[RiskException], max_duration_days: int = 365) -> None:
        self.entries = tuple(sorted(entries, key=lambda e: e.id))
        self.max_duration_days = max_duration_days

    def tracker(self, as_of: date) -> ExceptionTracker:
        """Start applying the register for one evaluation at ``as_of``."""
        return ExceptionTracker(self, as_of)


class ExceptionTracker:
    """Applies a register during one evaluation and remembers which entries matched."""

    def __init__(self, register: ExceptionRegister, as_of: date) -> None:
        self.register = register
        self.as_of = as_of
        self._used: set[str] = set()
        self._blocked: dict[str, set[str]] = {}

    def apply(self, control_id: str, rule: str, findings: list[Finding]) -> list[Finding]:
        """Return ``findings`` with ``excepted_by`` set where an active exception covers them.

        Matching but inactive (expired/pending) exceptions are remembered so the report can
        say *why* a deviation was not excused.
        """
        out = []
        for finding in findings:
            excepted_by = None
            for entry in self.register.entries:
                if not entry.covers(control_id, rule, finding):
                    continue
                if entry.state(self.as_of) is ExceptionState.ACTIVE:
                    excepted_by = entry.id
                    self._used.add(entry.id)
                    break
                self._blocked.setdefault(entry.id, set()).add(finding.resource)
            out.append(
                Finding(finding.resource, finding.message, excepted_by) if excepted_by else finding
            )
        return out

    def inactive_matches(self, control_id: str) -> list[str]:
        """Ids of expired/pending exceptions that would have covered findings of a control."""
        return sorted(
            entry.id
            for entry in self.register.entries
            if entry.control == control_id and entry.id in self._blocked
        )

    def report(self, expiring_within_days: int = 30) -> dict[str, Any]:
        rows = []
        for entry in self.register.entries:
            state = entry.state(self.as_of)
            days_left = (entry.expires_on - self.as_of).days
            flags = []
            if state is ExceptionState.ACTIVE and days_left <= expiring_within_days:
                flags.append("expiring-soon")
            if state is ExceptionState.ACTIVE and entry.id not in self._used:
                flags.append("unused")
            if entry.id in self._blocked:
                flags.append(f"{state.value}-but-matched")
            if (entry.expires_on - entry.approved_on).days > self.register.max_duration_days:
                flags.append("exceeds-max-duration")
            rows.append(
                {
                    **entry.to_dict(),
                    "state": state.value,
                    "days_left": days_left,
                    "flags": flags,
                    "matched_resources": sorted(self._blocked.get(entry.id, set())),
                }
            )
        return {
            "as_of": self.as_of.isoformat(),
            "max_duration_days": self.register.max_duration_days,
            "entries": rows,
        }


def load_exceptions(path: Path | None, library: Library) -> ExceptionRegister:
    """Load and validate the register. ``None`` means "no register" (an empty one)."""
    if path is None:
        return ExceptionRegister([])
    data = load_yaml(path, ExceptionRegisterError)
    doc = Settings(data or {}, path.name, ExceptionRegisterError, path.parent)
    return parse_exceptions(doc, library)


def parse_exceptions(doc: Settings, library: Library) -> ExceptionRegister:
    doc.reject_unknown({"policy", "exceptions"})
    policy = doc.mapping("policy")
    policy.reject_unknown({"max_duration_days"})
    max_days = policy.integer("max_duration_days", 365, minimum=1)
    entries: list[RiskException] = []
    seen: set[str] = set()
    for item in doc.items("exceptions"):
        item.reject_unknown(ENTRY_KEYS)
        exc_id = item.text("id")
        if not _EXC_ID.match(exc_id):
            raise ExceptionRegisterError(
                f"{item.where}.id: {exc_id!r} must look like 'EXC-2026-001'"
            )
        if exc_id in seen:
            raise ExceptionRegisterError(f"{item.where}: duplicate exception id {exc_id}")
        seen.add(exc_id)
        control_id = item.text("control")
        if control_id not in library.control_ids:
            raise ExceptionRegisterError(f"{exc_id}: unknown control {control_id}")
        rule = item.optional_text("rule")
        if rule is not None and rule not in {r.name for r in library.control(control_id).rules}:
            raise ExceptionRegisterError(f"{exc_id}: control {control_id} has no rule {rule}")
        resources = item.text_list("resources")
        if not resources:
            raise ExceptionRegisterError(f"{exc_id}: resources must list at least one pattern")
        approved_on = item.day("approved_on")
        expires_on = item.day("expires_on")
        if expires_on < approved_on:
            raise ExceptionRegisterError(f"{exc_id}: expires_on is before approved_on")
        entries.append(
            RiskException(
                id=exc_id,
                control=control_id,
                rule=rule,
                resources=tuple(resources),
                reason=item.text("reason"),
                compensating_controls=tuple(item.text_list("compensating_controls", [])),
                risk_owner=item.text("risk_owner"),
                approved_by=item.text("approved_by"),
                approved_on=approved_on,
                expires_on=expires_on,
            )
        )
    return ExceptionRegister(entries, max_days)
