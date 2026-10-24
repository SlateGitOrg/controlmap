"""Rules over the HR roster."""

from __future__ import annotations

from ..model import Finding
from .base import Param, RuleContext, RuleOutcome, as_date, days_between, rule


@rule(
    "hris.security_training",
    description="Active personnel completed security-awareness training within the window.",
    requires=("hris.roster",),
    params=[
        Param("max_age_days", "int", 365, "Training must be at most this old"),
        Param("new_hire_grace_days", "int", 30, "New hires have this long to complete it"),
    ],
)
def security_training(ctx: RuleContext) -> RuleOutcome:
    staff = [e for _, e in ctx.items("hris.roster", "employees") if e["status"] == "active"]
    max_age = ctx.param("max_age_days")
    grace = ctx.param("new_hire_grace_days")
    findings = []
    for person in staff:
        completed = as_date(person["training_completed_on"], f"{person['email']} training")
        started = as_date(person["start_date"], f"{person['email']} start_date")
        if completed is None:
            if started is not None and days_between(started, ctx.as_of) <= grace:
                continue
            findings.append(Finding(person["email"], "security training never completed"))
        elif days_between(completed, ctx.as_of) > max_age:
            age = days_between(completed, ctx.as_of)
            findings.append(
                Finding(person["email"], f"training is {age} days old (limit {max_age})")
            )
    return RuleOutcome(len(staff), findings)
