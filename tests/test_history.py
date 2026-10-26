"""Accumulated history must not change today's verdicts.

Regression tests for two ways old records leaked into evaluation: superseded documents kept
next to the current one made document-backed controls STALE, and subjects a source stopped
reporting (a repository removed from the config) were evaluated on their last record forever.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml

from controlmap.engine import evaluate, latest_runs, select_evidence
from controlmap.errors import EvidenceError
from controlmap.exceptions import ExceptionRegister
from controlmap.model import Evidence, Status
from controlmap.project import collect, evaluate_project, load_config
from controlmap.store import CollectionRun, EvidenceStore

from .conftest import AS_OF, at, ev
from .test_engine import ctrl, lib
from .test_rules_documents import doc

NONE = ExceptionRegister([])
REVIEW = {"rule": "manual.document_current", "params": {"doc_kind": "access_review"}}


def rule_result(records: list[Evidence], as_of: date = AS_OF) -> Any:
    run = evaluate(lib(ctrl("AC-05", REVIEW, freshness_days=400)), records, NONE, as_of, "Co")
    return run.controls[0].rules[0]


def test_superseded_document_does_not_make_the_control_stale() -> None:
    old = doc("access-review-2025-q2", "2025-04-14")  # 535 days before AS_OF
    current = doc("access-review-2026-q3", "2026-07-15")
    result = rule_result([old, current])
    assert result.status is Status.PASS, result.notes
    assert [ref.subject for ref in result.evidence] == ["access-review-2026-q3"]
    assert not any("days old" in note for note in result.notes)


def test_the_document_relied_on_still_goes_stale() -> None:
    only_old = doc("access-review-2025-q2", "2025-04-14")
    result = rule_result([only_old])
    # The rule's own cadence check fails first; freshness is still reported on that record.
    assert result.status is Status.FAIL
    assert any("is 535 days old (freshness window 400 days)" in n for n in result.notes)
    lenient = evaluate(
        lib(
            ctrl("AC-05", {**REVIEW, "params": {"doc_kind": "access_review", "max_age_days": 999}})
        ),
        [only_old],
        NONE,
        AS_OF,
        "Co",
    ).controls[0]
    assert lenient.status is Status.STALE


def test_rules_that_report_nothing_used_keep_every_ref() -> None:
    # Before any document was performed, the rule tests nothing and cites what it looked at.
    planned = doc("q4", "2026-12-01")
    planned = ev(planned.kind, planned.data, subject="q4", collected="2026-09-30")
    result = rule_result([planned])
    assert result.status is Status.NO_EVIDENCE
    assert [ref.subject for ref in result.evidence] == ["q4"]


def repo(name: str, collected: str, source: str = "github") -> Evidence:
    return ev("github.branch", {"repo": name}, subject=name, collected=collected, source=source)


def run_of(source: str, recorded: str, *records: Evidence) -> CollectionRun:
    return CollectionRun.from_records(source, records, at(recorded, 20))


def subjects(selected: dict[str, list[Evidence]]) -> list[str]:
    return [r.subject for r in selected.get("github.branch", [])]


def test_subjects_dropped_from_the_latest_run_are_retired() -> None:
    a1, b1 = repo("acme/a", "2026-09-01"), repo("acme/b", "2026-09-01")
    a2 = repo("acme/a", "2026-09-20")
    runs = [run_of("github", "2026-09-01", a1, b1), run_of("github", "2026-09-20", a2)]
    records = [a1, b1, a2]
    assert subjects(select_evidence(records, AS_OF)) == ["acme/a", "acme/b"]  # no runs: legacy
    assert subjects(select_evidence(records, AS_OF, runs)) == ["acme/a"]
    # Point in time: before the second run applied, acme/b was still reported.
    assert subjects(select_evidence(records, date(2026, 9, 10), runs)) == ["acme/a", "acme/b"]


def test_retirement_is_per_source_and_respects_newer_records() -> None:
    a1, b1 = repo("acme/a", "2026-09-01"), repo("acme/b", "2026-09-01")
    other = repo("acme/x", "2026-09-01", source="github-api")
    b_readded = repo("acme/b", "2026-09-25")  # collected after the run that dropped it
    runs = [
        run_of("github", "2026-09-01", a1, b1),
        run_of("github", "2026-09-20", repo("acme/a", "2026-09-20")),
    ]
    selected = select_evidence([a1, b1, other, b_readded], AS_OF, runs)
    assert subjects(selected) == ["acme/a", "acme/b", "acme/x"]
    assert selected["github.branch"][1] is b_readded


def test_latest_run_is_chosen_by_run_time_among_applicable_runs() -> None:
    late_doc = repo("doc-new", "2026-09-28")
    first = run_of("docs", "2026-09-01", repo("doc-old", "2026-08-01"), late_doc)
    # A later run whose newest record is older (the newest descriptor was deleted) still wins.
    second = run_of("docs", "2026-09-29", repo("doc-old", "2026-08-01"))
    future = run_of("docs", "2026-10-20", repo("doc-old", "2026-10-15"))
    empty = CollectionRun.from_records("empty", [], at("2026-09-02"))
    chosen = latest_runs([future, first, second, empty], AS_OF)
    assert chosen["docs"] is second
    assert chosen["empty"].collected_through == at("2026-09-02")
    # Runs apply from their newest record's date, not from when they ran.
    assert latest_runs([first, second], date(2026, 9, 27)) == {"docs": second}
    assert latest_runs([first, second], date(2026, 7, 31)) == {}


def test_run_manifests_round_trip_and_detect_tampering(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    assert store.runs() == []
    run = run_of("github", "2026-09-01", repo("acme/a", "2026-09-01"))
    digest = store.put_run(run)
    assert store.put_run(run) == digest  # idempotent
    assert store.runs() == [run]
    path = tmp_path / "runs" / f"{digest}.json"
    doc_ = json.loads(path.read_bytes())
    doc_["subjects"] = []
    path.write_text(json.dumps(doc_))
    with pytest.raises(EvidenceError, match="does not match its content digest"):
        store.runs()
    path.write_text(json.dumps({**doc_, "format": "other"}))
    with pytest.raises(EvidenceError, match="controlmap-run/1"):
        store.runs()
    path.write_text(json.dumps({"format": "controlmap-run/1"}))
    with pytest.raises(EvidenceError, match="malformed collection run"):
        store.runs()
    path.write_bytes(b"{")
    with pytest.raises(EvidenceError, match="cannot read collection run"):
        store.runs()


def test_acme_old_access_review_kept_in_the_folder(acme: Path) -> None:
    """A 2025 review next to the current Q3 2026 one."""
    descriptor = {
        "kind": "access_review",
        "title": "Q2 2025 production access review",
        "performed_on": "2025-04-14",
        "approved_by": "VP Engineering",
        "approved_on": "2025-04-15",
        "recorded_at": "2025-04-16T12:00:00Z",
    }
    path = acme / "data" / "documents" / "access-review-2025-q2.yaml"
    path.write_text(yaml.safe_dump(descriptor), encoding="utf-8")
    config = load_config(acme / "controlmap.yaml")
    assert collect(config).ok
    ac05 = next(c for c in evaluate_project(config).run.controls if c.control_id == "AC-05")
    assert ac05.status is Status.PASS, ac05.rules[0].notes
    assert [r.subject for r in ac05.rules[0].evidence] == ["access-review-2026-q3"]


def test_acme_repo_removed_from_config_is_no_longer_evaluated(acme: Path) -> None:
    config_path = acme / "controlmap.yaml"
    config = load_config(config_path)
    assert collect(config, clock=lambda: at("2026-09-30", 10)).ok
    doc_ = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    github = doc_["collectors"][0]
    github["repos"] = [r for r in github["repos"] if r["repo"] != "acme/web"]
    config_path.write_text(yaml.safe_dump(doc_, sort_keys=False), encoding="utf-8")
    config = load_config(config_path)
    assert collect(config, only={"github"}, clock=lambda: at("2026-09-30", 12)).ok
    controls = {c.control_id: c for c in evaluate_project(config).run.controls}
    cited = {ref.subject for r in controls["CM-01"].rules for ref in r.evidence}
    assert not any("acme/web" in s for s in cited)
    assert controls["CM-01"].status is Status.PASS  # the only failing repo is gone
