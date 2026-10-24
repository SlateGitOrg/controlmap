"""Exception register: validation, lifecycle states, matching and reporting."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from controlmap.errors import ExceptionRegisterError
from controlmap.exceptions import ExceptionState, load_exceptions, parse_exceptions
from controlmap.library import load_library
from controlmap.model import Finding
from controlmap.settings import Settings

from .conftest import ACME

LIBRARY = load_library(ACME / "library" / "controls.yaml")


def entry(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "EXC-2026-010",
        "control": "NW-02",
        "rule": "cloud.admin_ports_restricted",
        "resources": ["sg:sg-0bastion*"],
        "reason": "migration",
        "risk_owner": "Head of Infrastructure",
        "approved_by": "CISO",
        "approved_on": "2026-01-01",
        "expires_on": "2026-06-30",
    }
    data.update(over)
    return data


def register(*entries: dict[str, Any], **doc: Any) -> Any:
    return parse_exceptions(
        Settings({"exceptions": list(entries), **doc}, "exc", ExceptionRegisterError), LIBRARY
    )


def test_states_follow_approval_and_expiry_dates() -> None:
    [exc] = register(entry()).entries
    assert exc.state(date(2025, 12, 31)) is ExceptionState.PENDING
    assert exc.state(date(2026, 1, 1)) is ExceptionState.ACTIVE
    assert exc.state(date(2026, 6, 30)) is ExceptionState.ACTIVE
    assert exc.state(date(2026, 7, 1)) is ExceptionState.EXPIRED


def test_matching_uses_control_rule_and_resource_patterns() -> None:
    [exc] = register(entry()).entries
    bastion = Finding("sg:sg-0bastion1", "port 22")
    assert exc.covers("NW-02", "cloud.admin_ports_restricted", bastion)
    assert not exc.covers("NW-01", "cloud.admin_ports_restricted", bastion)
    assert not exc.covers("NW-02", "other.rule", bastion)
    assert not exc.covers("NW-02", "cloud.admin_ports_restricted", Finding("sg:sg-web", "x"))
    [any_rule] = register(entry(rule=None)).entries
    assert any_rule.covers("NW-02", "other.rule", bastion)


def test_tracker_applies_only_active_entries_and_reports_usage() -> None:
    reg = register(
        entry(),
        entry(
            id="EXC-2025-001",
            approved_on="2025-01-01",
            expires_on="2025-12-31",
            resources=["sg:old*"],
        ),
        entry(
            id="EXC-2026-011",
            control="AC-01",
            rule=None,
            resources=["nobody@x.io"],
            expires_on="2026-03-20",
        ),
        entry(id="EXC-2026-012", approved_on="2026-01-01", expires_on="2027-06-01"),
        policy={"max_duration_days": 365},
    )
    tracker = reg.tracker(date(2026, 3, 1))
    findings = [
        Finding("sg:sg-0bastion1", "p22"),
        Finding("sg:old-1", "p22"),
        Finding("sg:web", "p22"),
    ]
    applied = tracker.apply("NW-02", "cloud.admin_ports_restricted", findings)
    assert [f.excepted_by for f in applied] == ["EXC-2026-010", None, None]
    assert tracker.inactive_matches("NW-02") == ["EXC-2025-001"]
    assert tracker.inactive_matches("AC-01") == []
    rows = {r["id"]: r for r in tracker.report()["entries"]}
    assert rows["EXC-2025-001"]["flags"] == ["expired-but-matched"]
    assert rows["EXC-2025-001"]["matched_resources"] == ["sg:old-1"]
    assert rows["EXC-2026-011"]["flags"] == ["expiring-soon", "unused"]
    assert rows["EXC-2026-012"]["flags"] == ["unused", "exceeds-max-duration"]
    assert rows["EXC-2026-010"]["state"] == "active"
    assert rows["EXC-2026-010"]["days_left"] == 121


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([entry(id="exc-1")], "must look like"),
        ([entry(), entry()], "duplicate exception id"),
        ([entry(control="ZZ-01")], "unknown control ZZ-01"),
        ([entry(rule="idp.mfa_enforced")], "has no rule idp.mfa_enforced"),
        ([entry(resources=[])], "at least one pattern"),
        ([entry(expires_on="2025-01-01")], "expires_on is before approved_on"),
        ([entry(approved_on="soon")], "not an ISO-8601"),
        ([entry(reason=None)], "missing required key 'reason'"),
        ([entry(ticket="X-1")], "unknown key"),
    ],
)
def test_validation_errors(entries: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ExceptionRegisterError, match=message):
        register(*entries)


def test_loading_files(tmp_path: Path) -> None:
    assert load_exceptions(None, LIBRARY).entries == ()
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert load_exceptions(empty, LIBRARY).entries == ()
    acme = load_exceptions(ACME / "exceptions.yaml", LIBRARY)
    assert [e.id for e in acme.entries] == [
        "EXC-2025-007",
        "EXC-2026-001",
        "EXC-2026-002",
        "EXC-2026-003",
    ]
