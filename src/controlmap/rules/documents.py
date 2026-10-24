"""Rules over manually maintained procedural evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..model import Finding
from .base import Param, RuleContext, RuleOutcome, as_date, days_between, rule


def _kinds(params: Mapping[str, Any]) -> tuple[str, ...]:
    return (f"manual.{params['doc_kind']}",)


@rule(
    "manual.document_current",
    description="The most recent document of a kind (policy, access review, IR test ...) was "
    "performed within the window and formally approved.",
    requires=_kinds,
    params=[
        Param("doc_kind", "str", None, "Descriptor kind, e.g. access_review", required=True),
        Param("max_age_days", "int", 365, "Most recent activity must be at most this old"),
        Param("require_approval", "bool", True, "approved_by and approved_on must be set"),
    ],
)
def document_current(ctx: RuleContext) -> RuleOutcome:
    kind = f"manual.{ctx.param('doc_kind')}"
    records = [
        r
        for r in ctx.records(kind)
        if (as_date(r.data["performed_on"], r.subject) or ctx.as_of) <= ctx.as_of
    ]
    if not records:
        return RuleOutcome(0, [], [f"no {kind} performed on or before {ctx.as_of.isoformat()}"])
    latest = max(records, key=lambda r: (str(r.data["performed_on"]), r.subject))
    performed = as_date(latest.data["performed_on"], latest.subject)
    assert performed is not None
    findings = []
    age = days_between(performed, ctx.as_of)
    limit = ctx.param("max_age_days")
    if age > limit:
        findings.append(
            Finding(
                latest.subject,
                f"most recent {ctx.param('doc_kind')} is {age} days old (limit {limit})",
            )
        )
    if ctx.param("require_approval") and not (
        latest.data["approved_by"] and latest.data["approved_on"]
    ):
        findings.append(Finding(latest.subject, "document has no recorded approval"))
    notes = [f"latest: {latest.data['title']} (performed {performed.isoformat()})"]
    return RuleOutcome(1, findings, notes, used=[latest])
