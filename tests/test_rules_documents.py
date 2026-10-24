"""Rules over manual (procedural) evidence."""

from __future__ import annotations

from typing import Any

import pytest

from controlmap.errors import RuleError
from controlmap.model import Evidence
from controlmap.rules import get_rule

from .conftest import ev, run_rule


def doc(subject: str, performed: str, **over: Any) -> Evidence:
    data: dict[str, Any] = {
        "kind": "access_review",
        "title": f"review {subject}",
        "performed_on": performed,
        "approved_by": "CISO",
        "approved_on": performed,
        "summary": None,
    }
    data.update(over)
    return ev("manual.access_review", data, subject=subject, collected=performed)


PARAMS = {"doc_kind": "access_review", "max_age_days": 100}


def test_document_current_uses_latest_document() -> None:
    outcome = run_rule(
        "manual.document_current", [doc("q2", "2026-04-14"), doc("q3", "2026-07-15")], PARAMS
    )
    assert outcome.findings == []
    assert outcome.notes == ["latest: review q3 (performed 2026-07-15)"]


def test_document_current_flags_old_and_unapproved() -> None:
    outcome = run_rule(
        "manual.document_current",
        [doc("q1", "2026-01-10", approved_by=None, approved_on=None)],
        PARAMS,
    )
    assert [f.message for f in outcome.findings] == [
        "most recent access_review is 264 days old (limit 100)",
        "document has no recorded approval",
    ]
    relaxed = dict(PARAMS, max_age_days=365, require_approval=False)
    assert (
        run_rule(
            "manual.document_current", [doc("q1", "2026-01-10", approved_by=None)], relaxed
        ).findings
        == []
    )


def test_document_current_ignores_documents_performed_after_as_of() -> None:
    outcome = run_rule("manual.document_current", [doc("future", "2026-12-01")], PARAMS)
    assert outcome.checked == 0
    assert "no manual.access_review performed" in outcome.notes[0]


def test_document_kind_parameter_is_required_and_drives_evidence_kind() -> None:
    spec = get_rule("manual.document_current")
    with pytest.raises(RuleError, match="requires parameter doc_kind"):
        spec.resolve_params({}, "test")
    params = spec.resolve_params({"doc_kind": "dr_test"}, "test")
    assert spec.required_kinds(params) == ("manual.dr_test",)
