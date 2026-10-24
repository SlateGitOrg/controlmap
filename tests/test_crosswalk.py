"""Crosswalk derived from the control library."""

from __future__ import annotations

import csv
import io

from controlmap.crosswalk import build_crosswalk
from controlmap.engine import evaluate
from controlmap.exceptions import ExceptionRegister
from controlmap.library import load_library
from controlmap.model import Status

from .conftest import ACME, AS_OF
from .test_rules_identity import user, users

LIBRARY = load_library(ACME / "library" / "controls.yaml")


def test_links_criteria_to_annex_a_through_controls() -> None:
    crosswalk = build_crosswalk(LIBRARY)
    rows = {row.id: row for row in crosswalk.criteria}
    assert rows["CC6.1"].controls == ("AC-01", "AC-02", "AC-06", "CR-01", "EP-01", "EP-04")
    assert "5.17" in rows["CC6.1"].iso and "8.24" in rows["CC6.1"].iso
    assert rows["CC6.1"].status is None  # no run given
    iso = {row.id: row for row in crosswalk.iso}
    assert iso["8.5"].controls == ("AC-01",)
    assert iso["8.5"].tsc == ("CC6.1",)
    assert iso["7.4"].controls == ()


def test_coverage_reports_gaps_honestly() -> None:
    coverage = build_crosswalk(LIBRARY).coverage()
    assert coverage["tsc_in_scope"] == 38  # 33 common criteria + 3 availability + 2 confidentiality
    assert coverage["tsc_covered"] == 38 - len(coverage["tsc_gaps"])
    assert "CC1.1" in coverage["tsc_gaps"]
    assert "A1.1" in coverage["tsc_gaps"]
    assert coverage["iso_total"] == 93


def test_statuses_roll_up_from_an_evaluation() -> None:
    run = evaluate(LIBRARY, [users(user("a@x.io", mfa_factors=[]))], ExceptionRegister([]), AS_OF, "Co")
    crosswalk = build_crosswalk(LIBRARY, run)
    rows = {row.id: row for row in crosswalk.criteria}
    assert rows["CC6.1"].status is Status.FAIL
    assert rows["CC1.1"].status is None


def test_csv_export_has_one_row_per_criterion_control_pair() -> None:
    rows = list(csv.DictReader(io.StringIO(build_crosswalk(LIBRARY).to_csv())))
    assert rows[0].keys() == {"tsc_criterion", "tsc_label", "control", "iso27001_annex_a", "status"}
    gaps = [r for r in rows if r["status"] == "GAP"]
    assert {r["tsc_criterion"] for r in gaps} == set(build_crosswalk(LIBRARY).tsc_gaps)
    cc61 = [r["control"] for r in rows if r["tsc_criterion"] == "CC6.1"]
    assert cc61 == ["AC-01", "AC-02", "AC-06", "CR-01", "EP-01", "EP-04"]
