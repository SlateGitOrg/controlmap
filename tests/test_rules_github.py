"""GitHub repository rules."""

from __future__ import annotations

from typing import Any

from controlmap.collectors.github import normalize_codeowners, normalize_protection
from controlmap.model import Evidence

from .conftest import ev, resources, run_rule

STRONG = {
    "required_status_checks": {"strict": True, "contexts": ["ci"]},
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "required_approving_review_count": 2,
    },
    "enforce_admins": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
}


def protection(subject: str, raw: dict[str, Any] | None) -> Evidence:
    return ev("github.branch_protection", normalize_protection(raw), subject=subject)


def codeowners(subject: str, text: str | None) -> Evidence:
    return ev("github.codeowners", normalize_codeowners(text, "CODEOWNERS"), subject=subject)


def test_branch_protection_passes_for_strong_settings() -> None:
    outcome = run_rule("github.branch_protection", [protection("o/r@main", STRONG)])
    assert (outcome.checked, outcome.findings) == (1, [])
    strict = run_rule(
        "github.branch_protection",
        [protection("o/r@main", STRONG)],
        {"min_approvals": 2, "require_code_owner_reviews": True},
    )
    assert strict.findings == []


def test_branch_protection_lists_every_weakness() -> None:
    weak = {"required_pull_request_reviews": {"required_approving_review_count": 0}}
    outcome = run_rule(
        "github.branch_protection",
        [protection("o/weak@main", weak), protection("o/none@main", None)],
        {"require_code_owner_reviews": True},
    )
    messages = {f.resource: f.message for f in outcome.findings}
    assert messages["o/none@main"] == "branch is not protected"
    assert messages["o/weak@main"] == (
        "requires 0 approval(s), policy minimum is 1; stale approvals are not dismissed on new "
        "commits; administrators can bypass protection; no required status checks; code-owner "
        "review is not required"
    )


def test_branch_protection_flags_missing_pull_requests() -> None:
    no_pr = {k: v for k, v in STRONG.items() if k != "required_pull_request_reviews"}
    outcome = run_rule(
        "github.branch_protection",
        [protection("o/r@main", no_pr)],
        {"require_dismiss_stale_reviews": False},
    )
    assert outcome.findings[0].message.startswith("pull requests are not required")


def test_no_history_rewrite() -> None:
    assert run_rule("github.no_history_rewrite", [protection("o/r@main", STRONG)]).findings == []
    loose = dict(STRONG, allow_force_pushes={"enabled": True}, allow_deletions={"enabled": True})
    outcome = run_rule(
        "github.no_history_rewrite", [protection("o/r@main", loose), protection("o/u@main", None)]
    )
    assert resources(outcome) == ["o/r@main", "o/u@main"]
    assert outcome.findings[0].message == "force pushes allowed; branch deletion allowed"


def test_codeowners_coverage_passes_with_catch_all_and_required_paths() -> None:
    text = "*  @o/eng\n/.github/workflows/  @o/platform\n"
    outcome = run_rule(
        "github.codeowners_coverage",
        [codeowners("o/r", text)],
        {"required_paths": [".github/workflows/deploy.yml", "src/x.py"]},
    )
    assert outcome.findings == []


def test_codeowners_coverage_flags_missing_file_issues_and_unowned_paths() -> None:
    text = "/docs/ @o/docs\n/secrets/   \n!negated @o/x\n/app/ not-an-owner\n"
    outcome = run_rule(
        "github.codeowners_coverage",
        [codeowners("o/r", text), codeowners("o/none", None)],
        {"required_paths": ["secrets/key.txt", "docs/readme.md"]},
    )
    messages = {f.resource: f.message for f in outcome.findings}
    assert messages["o/none"] == "no CODEOWNERS file"
    detail = messages["o/r"]
    assert "line 3: negated pattern" in detail
    assert "line 4: invalid owner(s): not-an-owner" in detail
    assert "no catch-all" in detail
    assert "secrets/key.txt has no owner" in detail
    assert "docs/readme.md" not in detail
