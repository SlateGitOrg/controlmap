"""Rules over GitHub repository settings."""

from __future__ import annotations

from ..collectors.codeowners import codeowners_from_evidence
from ..model import Finding
from .base import Param, RuleContext, RuleOutcome, rule


@rule(
    "github.branch_protection",
    description="Default branches require pull requests with peer review and passing checks.",
    requires=("github.branch_protection",),
    params=[
        Param("min_approvals", "int", 1, "Minimum required approving reviews"),
        Param("require_dismiss_stale_reviews", "bool", True, "New commits dismiss approvals"),
        Param("require_enforce_admins", "bool", True, "Rules also bind repository admins"),
        Param("require_status_checks", "bool", True, "At least one required status check"),
        Param("require_code_owner_reviews", "bool", False, "Code owners must approve"),
    ],
)
def branch_protection(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("github.branch_protection")
    for record in records:
        data = record.data
        problems: list[str] = []
        if not data["protected"]:
            problems.append("branch is not protected")
        else:
            if not data["pull_request_required"]:
                problems.append("pull requests are not required")
            if data["required_approvals"] < ctx.param("min_approvals"):
                problems.append(
                    f"requires {data['required_approvals']} approval(s), "
                    f"policy minimum is {ctx.param('min_approvals')}"
                )
            if ctx.param("require_dismiss_stale_reviews") and not data["dismiss_stale_reviews"]:
                problems.append("stale approvals are not dismissed on new commits")
            if ctx.param("require_enforce_admins") and not data["enforce_admins"]:
                problems.append("administrators can bypass protection")
            if ctx.param("require_status_checks") and not data["required_status_checks"]:
                problems.append("no required status checks")
            if ctx.param("require_code_owner_reviews") and not data["require_code_owner_reviews"]:
                problems.append("code-owner review is not required")
        if problems:
            findings.append(Finding(record.subject, "; ".join(problems)))
    return RuleOutcome(len(records), findings)


@rule(
    "github.no_history_rewrite",
    description="Protected branches forbid force pushes and deletion.",
    requires=("github.branch_protection",),
)
def no_history_rewrite(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("github.branch_protection")
    for record in records:
        problems = []
        if record.data["allow_force_pushes"]:
            problems.append("force pushes allowed")
        if record.data["allow_deletions"]:
            problems.append("branch deletion allowed")
        if problems:
            findings.append(Finding(record.subject, "; ".join(problems)))
    return RuleOutcome(len(records), findings)


@rule(
    "github.codeowners_coverage",
    description="Each repository has a valid CODEOWNERS file that assigns owners to "
    "every file (or at least to the listed sensitive paths).",
    requires=("github.codeowners",),
    params=[
        Param("require_catch_all", "bool", True, "A '*' rule with owners must exist"),
        Param("required_paths", "list", [], "Paths that must resolve to at least one owner"),
    ],
)
def codeowners_coverage(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("github.codeowners")
    required_paths = [str(p) for p in ctx.param("required_paths")]
    for record in records:
        if not record.data["found"]:
            findings.append(Finding(record.subject, "no CODEOWNERS file"))
            continue
        owners = codeowners_from_evidence(dict(record.data))
        problems = [f"line {issue.line}: {issue.message}" for issue in owners.issues]
        if ctx.param("require_catch_all") and not owners.has_catch_all:
            problems.append("no catch-all '*' rule with owners")
        for path in required_paths:
            if not owners.owners_for(path):
                problems.append(f"{path} has no owner")
        if problems:
            findings.append(Finding(record.subject, "; ".join(problems)))
    return RuleOutcome(len(records), findings)
