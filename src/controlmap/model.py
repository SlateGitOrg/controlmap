"""Core data model: evidence records, rule/control outcomes and statuses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any

from .canonical import canonical_json, sha256_bytes, to_jsonable
from .errors import EvidenceError
from .timeutil import isoformat, parse_datetime


@dataclass(frozen=True)
class Attachment:
    """A file referenced by an evidence record (e.g. a signed access-review PDF)."""

    name: str
    sha256: str
    size: int
    source_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "source_path": self.source_path,
        }


@dataclass(frozen=True)
class Evidence:
    """One normalized, timestamped observation about one subject.

    ``kind`` names the schema of ``data`` (e.g. ``idp.users``); ``subject`` identifies what
    was observed (a repository, a cloud account, an IdP tenant); ``source`` is the configured
    collector instance that produced it; ``origin`` records where the raw data came from.
    """

    kind: str
    subject: str
    source: str
    collected_at: datetime
    data: Mapping[str, Any]
    origin: str
    attachments: tuple[Attachment, ...] = ()

    def identity(self) -> dict[str, Any]:
        """The hashed portion of the record. ``origin`` is excluded so that relocating raw
        files does not change a digest; attachment digests are included."""
        return {
            "kind": self.kind,
            "subject": self.subject,
            "source": self.source,
            "collected_at": isoformat(self.collected_at),
            "data": to_jsonable(self.data),
            "attachments": [{"name": a.name, "sha256": a.sha256} for a in self.attachments],
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.identity()))

    def to_dict(self) -> dict[str, Any]:
        record = self.identity()
        record["origin"] = self.origin
        record["attachments"] = [a.to_dict() for a in self.attachments]
        record["digest"] = self.digest
        return record

    @classmethod
    def from_dict(cls, record: Mapping[str, Any]) -> Evidence:
        try:
            evidence = cls(
                kind=str(record["kind"]),
                subject=str(record["subject"]),
                source=str(record["source"]),
                collected_at=parse_datetime(record["collected_at"], field="collected_at"),
                data=dict(record["data"]),
                origin=str(record.get("origin", "")),
                attachments=tuple(
                    Attachment(
                        name=str(a["name"]),
                        sha256=str(a["sha256"]),
                        size=int(a.get("size", 0)),
                        source_path=str(a.get("source_path", "")),
                    )
                    for a in record.get("attachments", [])
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(f"malformed evidence record: {exc}") from exc
        claimed = record.get("digest")
        if claimed is not None and claimed != evidence.digest:
            raise EvidenceError(
                f"evidence digest mismatch for {evidence.kind}/{evidence.subject}: "
                f"recorded {claimed}, computed {evidence.digest}"
            )
        return evidence


class Status(StrEnum):
    """Outcome of a rule or control, ordered from best to worst."""

    PASS = "PASS"  # noqa: S105 - a status, not a password
    EXCEPTED = "EXCEPTED"
    STALE = "STALE"
    NO_EVIDENCE = "NO_EVIDENCE"
    FAIL = "FAIL"
    ERROR = "ERROR"

    @property
    def rank(self) -> int:
        return _STATUS_RANK[self]

    @property
    def is_effective(self) -> bool:
        """True when the control is operating (cleanly or under an approved exception)."""
        return self in (Status.PASS, Status.EXCEPTED)

    @staticmethod
    def worst(statuses: list[Status]) -> Status:
        if not statuses:
            return Status.NO_EVIDENCE
        return max(statuses, key=lambda s: s.rank)


_STATUS_RANK = {
    Status.PASS: 0,
    Status.EXCEPTED: 1,
    Status.STALE: 2,
    Status.NO_EVIDENCE: 3,
    Status.FAIL: 4,
    Status.ERROR: 5,
}


@dataclass(frozen=True)
class Finding:
    """A specific deviation found by a rule, e.g. one user without MFA."""

    resource: str
    message: str
    excepted_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"resource": self.resource, "message": self.message, "excepted_by": self.excepted_by}


@dataclass(frozen=True)
class EvidenceRef:
    """A pointer from a result to the evidence it relied on."""

    digest: str
    kind: str
    subject: str
    collected_at: datetime
    age_days: int
    stale: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "kind": self.kind,
            "subject": self.subject,
            "collected_at": isoformat(self.collected_at),
            "age_days": self.age_days,
            "stale": self.stale,
        }


@dataclass(frozen=True)
class RuleResult:
    """Outcome of one rule inside one control."""

    rule: str
    description: str
    status: Status
    checked: int
    findings: tuple[Finding, ...]
    evidence: tuple[EvidenceRef, ...]
    notes: tuple[str, ...] = ()
    params: Mapping[str, Any] = field(default_factory=dict)

    @property
    def open_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.excepted_by is None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "description": self.description,
            "status": self.status.value,
            "checked": self.checked,
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "notes": list(self.notes),
            "params": to_jsonable(self.params),
        }


@dataclass(frozen=True)
class ControlResult:
    """Outcome of one control: the worst of its rule outcomes."""

    control_id: str
    title: str
    owner: str
    status: Status
    rules: tuple[RuleResult, ...]
    tsc: tuple[str, ...]
    iso: tuple[str, ...]
    exceptions_applied: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "owner": self.owner,
            "status": self.status.value,
            "tsc": list(self.tsc),
            "iso": list(self.iso),
            "exceptions_applied": list(self.exceptions_applied),
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass(frozen=True)
class EvaluationRun:
    """Everything produced by one evaluation at a point in time."""

    company: str
    as_of: date
    controls: tuple[ControlResult, ...]
    exception_report: Mapping[str, Any]

    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in Status}
        for control in self.controls:
            counts[control.status.value] += 1
        return counts

    def control(self, control_id: str) -> ControlResult:
        for control in self.controls:
            if control.control_id == control_id:
                return control
        raise KeyError(control_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "company": self.company,
            "as_of": self.as_of.isoformat(),
            "counts": self.counts(),
            "controls": [c.to_dict() for c in self.controls],
            "exceptions": to_jsonable(self.exception_report),
        }
