"""End-to-end over the bundled sample company: collect -> evaluate -> package -> verify.

The expected status of every control is recorded with a reason in examples/acme/expected.yaml.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

from controlmap.model import Status
from controlmap.package import build_package, verify_package
from controlmap.project import collect, evaluate_project, load_config

from .conftest import ACME

EXPECTED = yaml.safe_load((ACME / "expected.yaml").read_text(encoding="utf-8"))


def test_every_control_matches_its_documented_outcome(acme: Path) -> None:
    config = load_config(acme / "controlmap.yaml")
    report = collect(config)
    assert report.ok
    assert report.total_new == 21
    assert collect(config).total_new == 0  # collection is idempotent
    run = evaluate_project(config).run
    actual = {c.control_id: c.status.value for c in run.controls}
    expected = {cid: spec["status"] for cid, spec in EXPECTED["controls"].items()}
    assert actual == expected
    assert run.counts() == {
        "PASS": 11,
        "EXCEPTED": 2,
        "STALE": 1,
        "NO_EVIDENCE": 1,
        "FAIL": 7,
        "ERROR": 0,
    }


def test_known_findings_and_exception_flags(acme: Path) -> None:
    config = load_config(acme / "controlmap.yaml")
    collect(config)
    run = evaluate_project(config).run
    findings = {
        c.control_id: sorted(f.resource for r in c.rules for f in r.findings) for c in run.controls
    }
    assert findings["AC-01"] == ["dev.k@acme.example"]
    assert findings["AC-03"] == ["eli@acme.example"]
    assert findings["CM-01"] == ["acme/web@main"]
    assert findings["EP-02"] == ["device:D-1004", "device:D-1005"]
    assert findings["EP-04"] == ["device:D-1005"]
    assert findings["NW-02"] == ["sg:sg-0bastion1"]
    flags = {e["id"]: e["flags"] for e in run.exception_report["entries"]}
    assert flags == {
        "EXC-2025-007": ["expired-but-matched"],
        "EXC-2026-001": [],
        "EXC-2026-002": ["expiring-soon"],
        "EXC-2026-003": ["unused"],
    }


def test_history_changes_the_answer(acme: Path) -> None:
    """Evaluating before the exports existed yields NO_EVIDENCE, not a stale PASS."""
    config = load_config(acme / "controlmap.yaml")
    collect(config)
    early = evaluate_project(config, date(2026, 7, 17)).run
    statuses = {c.control_id: c.status for c in early.controls}
    assert statuses["AC-01"] is Status.NO_EVIDENCE  # the IdP export is dated 2026-09-30
    assert statuses["IR-01"] is Status.FAIL
    access_review = early.control("AC-05").rules[0]
    assert access_review.status is Status.PASS  # Q3 review was not recorded until 2026-07-18
    assert (
        access_review.notes[0] == "latest: Q2 2026 production access review (performed 2026-04-14)"
    )


def test_package_from_fixture_verifies(acme: Path, tmp_path: Path) -> None:
    config = load_config(acme / "controlmap.yaml")
    collect(config)
    evaluation = evaluate_project(config)
    info = build_package(
        tmp_path / "pkg",
        run=evaluation.run,
        library=evaluation.library,
        library_source=config.library_path,
        records=evaluation.records,
        store=config.store(),
    )
    assert verify_package(info.path).ok
