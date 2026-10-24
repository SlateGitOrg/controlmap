"""Rules over IdP users and the HR roster (one pass and several fail cases per rule)."""

from __future__ import annotations

from typing import Any

import pytest

from controlmap.errors import RuleError
from controlmap.model import Evidence

from .conftest import ev, resources, run_rule


def user(email: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": email,
        "email": email,
        "status": "active",
        "type": "human",
        "mfa_factors": ["Okta Verify"],
        "mfa_enrolled": True,
        "last_login": "2026-09-29",
        "created": "2024-01-01",
        "groups": [],
        "is_admin": False,
    }
    base.update(over)
    if "mfa_factors" in over:
        base["mfa_enrolled"] = bool(over["mfa_factors"])
    return base


def users(*items: dict[str, Any]) -> Evidence:
    return ev("idp.users", {"tenant": "t", "admin_groups": [], "users": list(items)}, subject="idp:t")


def employee(email: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "employee_id": email.split("@")[0],
        "email": email,
        "status": "active",
        "start_date": "2023-01-01",
        "termination_date": None,
        "department": None,
        "manager_email": None,
        "training_completed_on": "2026-03-01",
    }
    base.update(over)
    return base


def roster(*items: dict[str, Any]) -> Evidence:
    return ev("hris.roster", {"employees": list(items)}, subject="hris:hr")


# -- idp.mfa_enforced ------------------------------------------------------------------------
def test_mfa_passes_when_every_active_human_is_enrolled() -> None:
    outcome = run_rule("idp.mfa_enforced", [users(user("a@x.io"), user("b@x.io"))])
    assert outcome.checked == 2
    assert outcome.findings == []


def test_mfa_flags_missing_and_disallowed_factors() -> None:
    outcome = run_rule(
        "idp.mfa_enforced",
        [users(user("a@x.io", mfa_factors=[]), user("b@x.io", mfa_factors=["SMS"]), user("c@x.io"))],
        {"disallowed_factors": ["sms"]},
    )
    assert resources(outcome) == ["a@x.io", "b@x.io"]
    messages = {f.resource: f.message for f in outcome.findings}
    assert "no MFA" in messages["a@x.io"]
    assert "disallowed" in messages["b@x.io"]


def test_mfa_ignores_inactive_and_service_accounts_by_default() -> None:
    evidence = users(
        user("gone@x.io", status="deprovisioned", mfa_factors=[]),
        user("svc@x.io", type="service", mfa_factors=[]),
    )
    assert run_rule("idp.mfa_enforced", [evidence]).checked == 0
    strict = run_rule("idp.mfa_enforced", [evidence], {"include_service_accounts": True})
    assert resources(strict) == ["svc@x.io"]


def test_mfa_counts_users_across_multiple_tenants() -> None:
    second = ev("idp.users", {"users": [user("z@y.io", mfa_factors=[])]}, subject="idp:other")
    outcome = run_rule("idp.mfa_enforced", [users(user("a@x.io")), second])
    assert outcome.checked == 2
    assert resources(outcome) == ["z@y.io"]


# -- idp.inactive_accounts -------------------------------------------------------------------
def test_inactive_accounts_pass_for_recent_logins() -> None:
    assert run_rule("idp.inactive_accounts", [users(user("a@x.io"))]).findings == []


def test_inactive_accounts_flags_idle_and_never_used() -> None:
    outcome = run_rule(
        "idp.inactive_accounts",
        [
            users(
                user("idle@x.io", last_login="2026-06-01"),
                user("never@x.io", last_login=None, created="2026-01-01"),
                user("new@x.io", last_login=None, created="2026-09-20"),
                user("svc@x.io", type="service", last_login="2026-01-01"),
            )
        ],
    )
    assert resources(outcome) == ["idle@x.io", "never@x.io", "svc@x.io"]
    idle = next(f for f in outcome.findings if f.resource == "idle@x.io")
    assert "122 days" in idle.message


def test_inactive_accounts_boundary_is_inclusive() -> None:
    # exactly 90 days idle is allowed; 91 is not
    ok = users(user("a@x.io", last_login="2026-07-03"))
    late = users(user("a@x.io", last_login="2026-07-02"))
    assert run_rule("idp.inactive_accounts", [ok]).findings == []
    assert resources(run_rule("idp.inactive_accounts", [late])) == ["a@x.io"]


def test_inactive_accounts_rejects_garbage_dates() -> None:
    with pytest.raises(RuleError, match="not a date"):
        run_rule("idp.inactive_accounts", [users(user("a@x.io", last_login="yesterday"))])


# -- idp.admin_accounts_limited --------------------------------------------------------------
def test_admins_pass_when_few_human_and_mfa() -> None:
    outcome = run_rule("idp.admin_accounts_limited", [users(user("a@x.io", is_admin=True))])
    assert outcome.checked == 1
    assert outcome.findings == []


def test_admins_flag_count_service_and_missing_mfa() -> None:
    admins = [user(f"a{i}@x.io", is_admin=True) for i in range(3)]
    admins.append(user("svc@x.io", type="service", is_admin=True, mfa_factors=[]))
    outcome = run_rule("idp.admin_accounts_limited", [users(*admins)], {"max_admins": 2})
    assert resources(outcome) == ["idp:admins", "svc@x.io", "svc@x.io"]
    assert any("exceed the limit of 2" in f.message for f in outcome.findings)


# -- idp.leavers_deprovisioned ---------------------------------------------------------------
def test_leavers_pass_when_disabled_and_everyone_on_roster() -> None:
    outcome = run_rule(
        "idp.leavers_deprovisioned",
        [
            users(user("a@x.io"), user("gone@x.io", status="deprovisioned")),
            roster(
                employee("a@x.io"),
                employee("gone@x.io", status="terminated", termination_date="2026-09-01"),
            ),
        ],
    )
    assert outcome.findings == []
    assert outcome.checked == 2  # one leaver + one active account


def test_leavers_flag_late_deprovisioning_and_orphans() -> None:
    outcome = run_rule(
        "idp.leavers_deprovisioned",
        [
            users(user("late@x.io"), user("orphan@x.io"), user("svc@x.io", type="service")),
            roster(employee("late@x.io", status="terminated", termination_date="2026-09-12")),
        ],
    )
    assert resources(outcome) == ["late@x.io", "orphan@x.io"]
    late = next(f for f in outcome.findings if f.resource == "late@x.io")
    assert "19 days ago" in late.message


def test_leavers_respect_sla_and_future_terminations() -> None:
    evidence = [
        users(user("today@x.io"), user("future@x.io")),
        roster(
            employee("today@x.io", status="terminated", termination_date="2026-09-30"),
            employee("future@x.io", status="terminated", termination_date="2026-10-15"),
        ),
    ]
    assert run_rule("idp.leavers_deprovisioned", evidence, {"flag_orphans": False}).findings == []
    strict = run_rule("idp.leavers_deprovisioned", evidence, {"sla_days": 0, "flag_orphans": False})
    assert resources(strict) == ["today@x.io"]


# -- hris.security_training ------------------------------------------------------------------
def test_training_passes_for_current_staff() -> None:
    outcome = run_rule("hris.security_training", [roster(employee("a@x.io"))])
    assert (outcome.checked, outcome.findings) == (1, [])


def test_training_flags_never_and_expired_but_not_new_hires() -> None:
    outcome = run_rule(
        "hris.security_training",
        [
            roster(
                employee("never@x.io", training_completed_on=None),
                employee("old@x.io", training_completed_on="2025-09-01"),
                employee("new@x.io", training_completed_on=None, start_date="2026-09-20"),
                employee("left@x.io", status="terminated", training_completed_on=None),
            )
        ],
    )
    assert outcome.checked == 3
    assert resources(outcome) == ["never@x.io", "old@x.io"]
