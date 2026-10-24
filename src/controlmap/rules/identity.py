"""Rules over identity-provider users, cross-referenced with the HR roster."""

from __future__ import annotations

from typing import Any

from ..model import Finding
from .base import Param, RuleContext, RuleOutcome, as_date, days_between, rule

ACCESS_STATES = ("active", "pending")


def _humans(ctx: RuleContext, include_service: bool = False) -> list[dict[str, Any]]:
    return [
        user
        for _, user in ctx.items("idp.users", "users")
        if user["status"] == "active" and (include_service or user["type"] == "human")
    ]


@rule(
    "idp.mfa_enforced",
    description="Every active workforce account is enrolled in MFA with an allowed factor.",
    requires=("idp.users",),
    params=[
        Param("include_service_accounts", "bool", False, "Also require MFA for service accounts"),
        Param("disallowed_factors", "list", [], "Factors that do not count (e.g. sms, voice)"),
    ],
)
def mfa_enforced(ctx: RuleContext) -> RuleOutcome:
    users = _humans(ctx, ctx.param("include_service_accounts"))
    weak = {str(f).lower() for f in ctx.param("disallowed_factors")}
    findings = []
    for user in users:
        factors = [f for f in user["mfa_factors"] if f.lower() not in weak]
        if not user["mfa_factors"]:
            findings.append(Finding(user["email"], "no MFA factor enrolled"))
        elif not factors:
            listed = ", ".join(user["mfa_factors"])
            findings.append(
                Finding(user["email"], f"only disallowed MFA factors enrolled ({listed})")
            )
    return RuleOutcome(len(users), findings)


@rule(
    "idp.inactive_accounts",
    description="Active accounts unused for longer than the policy window are disabled.",
    requires=("idp.users",),
    params=[
        Param("max_days_since_login", "int", 90, "Maximum days since last sign-in"),
        Param("new_account_grace_days", "int", 30, "Grace period for never-used new accounts"),
    ],
)
def inactive_accounts(ctx: RuleContext) -> RuleOutcome:
    users = _humans(ctx, include_service=True)
    limit = ctx.param("max_days_since_login")
    grace = ctx.param("new_account_grace_days")
    findings = []
    for user in users:
        last = as_date(user["last_login"], f"{user['email']} last_login")
        if last is None:
            created = as_date(user["created"], f"{user['email']} created")
            if created is None or days_between(created, ctx.as_of) > grace:
                findings.append(Finding(user["email"], "account has never been used"))
            continue
        idle = days_between(last, ctx.as_of)
        if idle > limit:
            findings.append(Finding(user["email"], f"no sign-in for {idle} days (limit {limit})"))
    return RuleOutcome(len(users), findings)


@rule(
    "idp.admin_accounts_limited",
    description="Administrator accounts are few, human, and MFA-protected.",
    requires=("idp.users",),
    params=[Param("max_admins", "int", 5, "Maximum number of administrator accounts")],
)
def admin_accounts_limited(ctx: RuleContext) -> RuleOutcome:
    admins = [u for u in _humans(ctx, include_service=True) if u["is_admin"]]
    findings = []
    maximum = ctx.param("max_admins")
    if len(admins) > maximum:
        findings.append(
            Finding(
                "idp:admins", f"{len(admins)} administrator accounts exceed the limit of {maximum}"
            )
        )
    for admin in admins:
        if admin["type"] != "human":
            findings.append(Finding(admin["email"], "service account holds administrator rights"))
        if not admin["mfa_enrolled"]:
            findings.append(Finding(admin["email"], "administrator without MFA"))
    return RuleOutcome(len(admins), findings)


@rule(
    "idp.leavers_deprovisioned",
    description="Accounts of terminated personnel are disabled within the SLA, and every active "
    "human account belongs to someone on the HR roster.",
    requires=("idp.users", "hris.roster"),
    params=[
        Param("sla_days", "int", 1, "Days after termination by which access must be removed"),
        Param("flag_orphans", "bool", True, "Flag active accounts with no HR record"),
    ],
)
def leavers_deprovisioned(ctx: RuleContext) -> RuleOutcome:
    employees = {e["email"]: e for _, e in ctx.items("hris.roster", "employees")}
    accounts = [u for _, u in ctx.items("idp.users", "users")]
    by_email = {u["email"]: u for u in accounts}
    sla = ctx.param("sla_days")
    findings = []
    leavers = [e for e in employees.values() if e["status"] == "terminated"]
    for leaver in leavers:
        ended = as_date(leaver["termination_date"], f"{leaver['email']} termination_date")
        assert ended is not None  # the HRIS collector guarantees it for terminated rows
        if ended > ctx.as_of:
            continue
        account = by_email.get(leaver["email"])
        overdue = days_between(ended, ctx.as_of)
        if account and account["status"] in ACCESS_STATES and overdue > sla:
            findings.append(
                Finding(
                    leaver["email"],
                    f"terminated {ended.isoformat()} ({overdue} days ago) but IdP account "
                    f"is still {account['status']}",
                )
            )
    checked = len(leavers)
    if ctx.param("flag_orphans"):
        for account in accounts:
            if account["type"] != "human" or account["status"] not in ACCESS_STATES:
                continue
            checked += 1
            if account["email"] not in employees:
                findings.append(Finding(account["email"], "active account with no HR record"))
    return RuleOutcome(checked, findings)
