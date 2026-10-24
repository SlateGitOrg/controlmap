"""Point-in-time evaluation of the control library against stored evidence.

For an evaluation date ``as_of`` the engine:

1. selects, for every (kind, subject), the newest evidence collected on or before the end of
   ``as_of`` (later evidence is invisible, so past evaluations are reproducible);
2. runs every rule of every control on the evidence kinds it requires;
3. classifies each rule outcome, applying the exception register to its findings;
4. rolls rule statuses up to the control (worst wins).

Rule status decision table (first match wins):

=================================================  ===========
condition                                          status
=================================================  ===========
rule raised an error while reading evidence         ERROR
a required evidence kind has no record             NO_EVIDENCE
at least one finding not covered by an exception   FAIL
the rule checked zero items                        NO_EVIDENCE
any evidence used is older than freshness window   STALE
all findings covered by active exceptions          EXCEPTED
otherwise                                          PASS
=================================================  ===========

A failing rule stays FAIL even if its evidence is also stale: a known deviation is more
important than the age of the proof.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import date

from .errors import ControlmapError
from .exceptions import ExceptionRegister, ExceptionTracker
from .library import Control, ControlRule, Library
from .model import (
    ControlResult,
    EvaluationRun,
    Evidence,
    EvidenceRef,
    Finding,
    RuleResult,
    Status,
)
from .rules import RuleContext

log = logging.getLogger(__name__)


def select_evidence(records: Iterable[Evidence], as_of: date) -> dict[str, list[Evidence]]:
    """Group records by kind, keeping the newest per subject collected on/before ``as_of``."""
    best: dict[tuple[str, str], Evidence] = {}
    for record in records:
        if record.collected_at.date() > as_of:
            continue
        key = (record.kind, record.subject)
        current = best.get(key)
        if current is None or (record.collected_at, record.digest) > (
            current.collected_at,
            current.digest,
        ):
            best[key] = record
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for (kind, _), record in sorted(best.items()):
        grouped[kind].append(record)
    return dict(grouped)


def evaluate(
    library: Library,
    records: Iterable[Evidence],
    register: ExceptionRegister,
    as_of: date,
    company: str,
) -> EvaluationRun:
    selected = select_evidence(records, as_of)
    tracker = register.tracker(as_of)
    results = [_evaluate_control(control, selected, as_of, tracker) for control in library.controls]
    run = EvaluationRun(company, as_of, tuple(results), tracker.report())
    log.info("evaluated %d controls as of %s: %s", len(results), as_of, run.counts())
    return run


def _evaluate_control(
    control: Control,
    selected: dict[str, list[Evidence]],
    as_of: date,
    tracker: ExceptionTracker,
) -> ControlResult:
    rule_results = tuple(
        _evaluate_rule(control, control_rule, selected, as_of, tracker)
        for control_rule in control.rules
    )
    applied = sorted(
        {f.excepted_by for r in rule_results for f in r.findings if f.excepted_by is not None}
    )
    notes = tuple(
        f"exception {exc_id} matched findings but is not active on {as_of.isoformat()}"
        for exc_id in tracker.inactive_matches(control.id)
    )
    return ControlResult(
        control_id=control.id,
        title=control.title,
        owner=control.owner,
        status=Status.worst([r.status for r in rule_results]),
        rules=rule_results,
        tsc=control.tsc,
        iso=control.iso,
        exceptions_applied=tuple(applied),
        notes=notes,
    )


def _refs(records: Sequence[Evidence], as_of: date, freshness_days: int) -> list[EvidenceRef]:
    refs = []
    for record in records:
        age = (as_of - record.collected_at.date()).days
        refs.append(
            EvidenceRef(
                digest=record.digest,
                kind=record.kind,
                subject=record.subject,
                collected_at=record.collected_at,
                age_days=age,
                stale=age > freshness_days,
            )
        )
    return refs


def _evaluate_rule(
    control: Control,
    control_rule: ControlRule,
    selected: dict[str, list[Evidence]],
    as_of: date,
    tracker: ExceptionTracker,
) -> RuleResult:
    spec = control_rule.spec
    kinds = control_rule.required_kinds()
    evidence = {kind: selected.get(kind, []) for kind in (*kinds, *spec.optional)}
    refs = [
        ref
        for kind in sorted(evidence)
        for ref in _refs(evidence[kind], as_of, control_rule.freshness_days)
    ]

    def result(
        status: Status,
        checked: int = 0,
        findings: Sequence[Finding] = (),
        notes: Sequence[str] = (),
    ) -> RuleResult:
        return RuleResult(
            rule=spec.name,
            description=spec.description,
            status=status,
            checked=checked,
            findings=tuple(findings),
            evidence=tuple(refs),
            notes=tuple(notes),
            params=control_rule.params,
        )

    missing = [kind for kind in kinds if not evidence[kind]]
    if missing:
        return result(
            Status.NO_EVIDENCE,
            notes=[
                f"no {kind} evidence collected on or before {as_of.isoformat()}" for kind in missing
            ],
        )
    try:
        outcome = spec.func(RuleContext(as_of, control_rule.params, evidence))
    except (ControlmapError, KeyError, TypeError, ValueError, AttributeError) as exc:
        log.warning("%s/%s raised %s", control.id, spec.name, exc)
        return result(Status.ERROR, notes=[f"rule error: {type(exc).__name__}: {exc}"])

    findings = tracker.apply(control.id, spec.name, outcome.findings)
    notes = list(outcome.notes)
    stale = [ref for ref in refs if ref.stale]
    for ref in stale:
        notes.append(
            f"{ref.kind} for {ref.subject} is {ref.age_days} days old "
            f"(freshness window {control_rule.freshness_days} days)"
        )
    open_findings = [f for f in findings if f.excepted_by is None]
    if open_findings:
        status = Status.FAIL
    elif outcome.checked == 0:
        status = Status.NO_EVIDENCE
        notes.append("the rule's population is empty; nothing was tested")
    elif stale:
        status = Status.STALE
    elif findings:
        status = Status.EXCEPTED
    else:
        status = Status.PASS
    return result(status, outcome.checked, findings, notes)
