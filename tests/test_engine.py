"""Evaluation engine: evidence selection, the status decision table and roll-up."""

from __future__ import annotations

from datetime import date
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from controlmap.engine import evaluate, select_evidence
from controlmap.errors import ExceptionRegisterError, LibraryError
from controlmap.exceptions import ExceptionRegister, parse_exceptions
from controlmap.frameworks import load_catalogs
from controlmap.library import Library, parse_library
from controlmap.model import Evidence, Status
from controlmap.settings import Settings

from .conftest import AS_OF, ev
from .test_rules_endpoint import device, inventory
from .test_rules_identity import user, users

CATALOGS = load_catalogs()


def lib(*controls: dict[str, Any]) -> Library:
    return parse_library(Settings({"controls": list(controls)}, "lib", LibraryError), CATALOGS)


def ctrl(control_id: str, *rules: dict[str, Any], **over: Any) -> dict[str, Any]:
    return {"id": control_id, "title": control_id, "tsc": ["CC6.1"], "rules": list(rules), **over}


MFA = {"rule": "idp.mfa_enforced"}
DISK = {"rule": "endpoint.disk_encryption"}
OS = {"rule": "endpoint.os_supported"}
NONE = ExceptionRegister([])


def status_of(
    library: Library, records: list[Evidence], register: ExceptionRegister = NONE
) -> dict[str, Status]:
    run = evaluate(library, records, register, AS_OF, "Co")
    return {c.control_id: c.status for c in run.controls}


def test_pass_fail_and_no_evidence() -> None:
    library = lib(ctrl("AC-01", MFA), ctrl("EP-01", DISK))
    good = users(user("a@x.io"))
    bad = users(user("a@x.io", mfa_factors=[]))
    assert status_of(library, [good]) == {"AC-01": Status.PASS, "EP-01": Status.NO_EVIDENCE}
    assert status_of(library, [bad])["AC-01"] is Status.FAIL


def test_empty_population_is_no_evidence_not_pass() -> None:
    only_service = users(user("svc@x.io", type="service"))
    run = evaluate(lib(ctrl("AC-01", MFA)), [only_service], NONE, AS_OF, "Co")
    result = run.controls[0].rules[0]
    assert result.status is Status.NO_EVIDENCE
    assert "population is empty" in result.notes[-1]


def test_rule_errors_become_error_status() -> None:
    run = evaluate(
        lib(ctrl("EP-03", OS)), [inventory(device("D1", os_version="n/a"))], NONE, AS_OF, "Co"
    )
    result = run.controls[0].rules[0]
    assert result.status is Status.ERROR
    assert result.notes[0].startswith("rule error: RuleError")


def test_staleness_and_freshness_overrides() -> None:
    old = inventory(device("D1"))
    old = Evidence(
        old.kind, old.subject, old.source, old.collected_at.replace(month=7), old.data, "o"
    )
    assert status_of(lib(ctrl("EP-01", DISK)), [old])["EP-01"] is Status.STALE
    relaxed = lib(ctrl("EP-01", DISK, freshness_days=70))
    assert status_of(relaxed, [old])["EP-01"] is Status.PASS
    per_rule = lib(ctrl("EP-01", {"rule": "endpoint.disk_encryption", "freshness_days": 90}))
    assert status_of(per_rule, [old])["EP-01"] is Status.PASS


def test_fail_takes_precedence_over_stale() -> None:
    record = inventory(device("D1", disk_encrypted=False))
    stale = Evidence(
        record.kind,
        record.subject,
        record.source,
        record.collected_at.replace(year=2025),
        record.data,
        "o",
    )
    run = evaluate(lib(ctrl("EP-01", DISK)), [stale], NONE, AS_OF, "Co")
    result = run.controls[0].rules[0]
    assert result.status is Status.FAIL
    assert any("days old" in note for note in result.notes)
    assert result.evidence[0].stale is True


def register(*entries: dict[str, Any], library: Library) -> ExceptionRegister:
    return parse_exceptions(
        Settings({"exceptions": list(entries)}, "exc", ExceptionRegisterError), library
    )


def exc(exc_id: str, approved: str, expires: str) -> dict[str, Any]:
    return {
        "id": exc_id,
        "control": "AC-01",
        "resources": ["a@*"],
        "reason": "r",
        "risk_owner": "o",
        "approved_by": "CISO",
        "approved_on": approved,
        "expires_on": expires,
    }


def test_exceptions_turn_fail_into_excepted_only_while_active() -> None:
    library = lib(ctrl("AC-01", MFA))
    bad = users(user("a@x.io", mfa_factors=[]), user("b@x.io"))
    active = register(exc("EXC-1", "2026-01-01", "2026-12-31"), library=library)
    run = evaluate(library, [bad], active, AS_OF, "Co")
    assert run.controls[0].status is Status.EXCEPTED
    assert run.controls[0].exceptions_applied == ("EXC-1",)
    assert run.controls[0].rules[0].open_findings == ()

    expired = register(exc("EXC-2", "2025-01-01", "2025-12-31"), library=library)
    run = evaluate(library, [bad], expired, AS_OF, "Co")
    assert run.controls[0].status is Status.FAIL
    assert run.controls[0].notes == (
        "exception EXC-2 matched findings but is not active on 2026-10-01",
    )

    partial = users(user("a@x.io", mfa_factors=[]), user("c@x.io", mfa_factors=[]))
    assert status_of(library, [partial], active)["AC-01"] is Status.FAIL


def test_control_rolls_up_worst_rule() -> None:
    library = lib(ctrl("AC-01", MFA, DISK))
    run = evaluate(library, [users(user("a@x.io"))], NONE, AS_OF, "Co")
    assert [r.status for r in run.controls[0].rules] == [Status.PASS, Status.NO_EVIDENCE]
    assert run.controls[0].status is Status.NO_EVIDENCE
    assert run.counts()["NO_EVIDENCE"] == 1
    assert run.control("AC-01").title == "AC-01"


def snapshot(day: str, factors: list[str]) -> Evidence:
    return ev(
        "idp.users",
        {"users": [user("a@x.io", mfa_factors=factors)]},
        subject="idp:t",
        collected=day,
    )


def test_point_in_time_selection_ignores_future_evidence() -> None:
    june, sept = snapshot("2026-06-30", []), snapshot("2026-09-30", ["totp"])
    assert select_evidence([june, sept], date(2026, 10, 1))["idp.users"] == [sept]
    assert select_evidence([june, sept], date(2026, 7, 1))["idp.users"] == [june]
    assert select_evidence([june, sept], date(2026, 6, 29)) == {}
    library = lib(ctrl("AC-01", MFA, freshness_days=400))
    run_now = evaluate(library, [june, sept], NONE, date(2026, 10, 1), "Co")
    run_then = evaluate(library, [june, sept], NONE, date(2026, 7, 1), "Co")
    assert run_now.controls[0].status is Status.PASS
    assert run_then.controls[0].status is Status.FAIL


def test_same_timestamp_tie_break_is_deterministic() -> None:
    a, b = snapshot("2026-09-30", []), snapshot("2026-09-30", ["totp"])
    chosen = select_evidence([a, b], AS_OF)["idp.users"][0]
    assert chosen == select_evidence([b, a], AS_OF)["idp.users"][0]
    assert chosen.digest == max(a.digest, b.digest)


RECORDS = [
    snapshot("2026-06-30", []),
    snapshot("2026-09-30", ["totp"]),
    inventory(device("D1")),
    inventory(device("D2", disk_encrypted=False)),
    ev("idp.users", {"users": [user("z@y.io", mfa_factors=[])]}, subject="idp:other"),
]


@settings(max_examples=40, deadline=None)
@given(st.permutations(RECORDS))
def test_results_do_not_depend_on_record_order(records: list[Evidence]) -> None:
    library = lib(ctrl("AC-01", MFA), ctrl("EP-01", DISK))
    baseline = evaluate(library, RECORDS, NONE, AS_OF, "Co").to_dict()
    assert evaluate(library, records, NONE, AS_OF, "Co").to_dict() == baseline
