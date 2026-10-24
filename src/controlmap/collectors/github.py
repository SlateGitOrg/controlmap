"""GitHub repository settings: branch protection and CODEOWNERS.

Two modes, producing identical evidence:

* **file mode** — each repository entry points at saved REST responses, e.g. the output of
  ``gh api repos/OWNER/REPO/branches/main/protection > main.protection.json`` and a copy of
  the CODEOWNERS file. ``protection: null`` records that the API answered 404
  ("Branch not protected").
* **api mode** — ``api.base_url`` is set; the collector calls the GitHub REST API (or any
  server speaking the same shapes, such as the bundled mock in :mod:`controlmap.mockapi`).

Evidence kinds: ``github.branch_protection`` (subject ``owner/repo@branch``) and
``github.codeowners`` (subject ``owner/repo``).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import urllib.parse
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from ..errors import CollectorError
from ..model import Evidence
from ..settings import Settings
from .base import Collector, CollectorContext, read_text, register_collector
from .codeowners import parse_codeowners

log = logging.getLogger(__name__)

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def _enabled(block: Any) -> bool:
    """GitHub wraps several booleans as ``{"enabled": bool}``."""
    if isinstance(block, Mapping):
        return bool(block.get("enabled", False))
    return bool(block)


def normalize_protection(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize a branch-protection REST response (``None`` = branch not protected)."""
    if raw is None:
        return {
            "protected": False,
            "pull_request_required": False,
            "required_approvals": 0,
            "dismiss_stale_reviews": False,
            "require_code_owner_reviews": False,
            "enforce_admins": False,
            "required_status_checks": [],
            "strict_status_checks": False,
            "allow_force_pushes": True,
            "allow_deletions": True,
            "required_linear_history": False,
            "required_signatures": False,
        }
    if not isinstance(raw, Mapping):
        raise CollectorError("branch protection response must be a JSON object")
    reviews = raw.get("required_pull_request_reviews")
    checks = raw.get("required_status_checks") or {}
    if not isinstance(checks, Mapping):
        raise CollectorError("required_status_checks must be an object")
    contexts = {str(c) for c in checks.get("contexts") or []}
    contexts.update(
        str(c["context"])
        for c in checks.get("checks") or []
        if isinstance(c, Mapping) and "context" in c
    )
    approvals = 0
    if isinstance(reviews, Mapping):
        value = reviews.get("required_approving_review_count", 0)
        if isinstance(value, bool) or not isinstance(value, int):
            raise CollectorError("required_approving_review_count must be an integer")
        approvals = value
    return {
        "protected": True,
        "pull_request_required": isinstance(reviews, Mapping),
        "required_approvals": approvals,
        "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews", False))
        if isinstance(reviews, Mapping)
        else False,
        "require_code_owner_reviews": bool(reviews.get("require_code_owner_reviews", False))
        if isinstance(reviews, Mapping)
        else False,
        "enforce_admins": _enabled(raw.get("enforce_admins")),
        "required_status_checks": sorted(contexts),
        "strict_status_checks": bool(checks.get("strict", False)),
        "allow_force_pushes": _enabled(raw.get("allow_force_pushes")),
        "allow_deletions": _enabled(raw.get("allow_deletions")),
        "required_linear_history": _enabled(raw.get("required_linear_history")),
        "required_signatures": _enabled(raw.get("required_signatures")),
    }


def normalize_codeowners(text: str | None, path: str | None) -> dict[str, Any]:
    if text is None:
        return {"found": False, "path": None, "rules": [], "issues": []}
    parsed = parse_codeowners(text)
    return {
        "found": True,
        "path": path,
        "rules": [rule.to_dict() for rule in parsed.rules],
        "issues": [issue.to_dict() for issue in parsed.issues],
    }


class _RepoSpec:
    def __init__(self, settings: Settings, api_mode: bool) -> None:
        settings.reject_unknown(
            {"repo", "branch", "protection", "codeowners", "codeowners_location"}
        )
        self.repo = settings.text("repo")
        if self.repo.count("/") != 1 or not all(self.repo.split("/")):
            raise CollectorError(f"{settings.where}.repo: expected 'owner/name', got {self.repo!r}")
        self.branch = settings.optional_text("branch")
        self.where = settings.where
        self.protection_file: Path | None = None
        self.protection_unprotected = False
        self.codeowners_file: Path | None = None
        self.codeowners_location = settings.text("codeowners_location", CODEOWNERS_LOCATIONS[0])
        if api_mode:
            return
        if self.branch is None:
            raise CollectorError(f"{settings.where}: 'branch' is required in file mode")
        if "protection" not in settings.data:
            raise CollectorError(f"{settings.where}: 'protection' is required in file mode")
        if settings.raw("protection") is None:
            self.protection_unprotected = True
        else:
            self.protection_file = settings.path("protection")
        self.codeowners_file = settings.optional_path("codeowners")


@register_collector
class GitHubCollector(Collector):
    type_name: ClassVar[str] = "github"
    description: ClassVar[str] = (
        "Branch protection and CODEOWNERS from saved REST responses or the API"
    )
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"repos", "api"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.api: Settings | None = settings.mapping("api") if settings.has("api") else None
        if self.api is not None:
            self.api.reject_unknown({"base_url", "token_env"})
        self.repos = [_RepoSpec(item, self.api is not None) for item in settings.items("repos")]
        if not self.repos:
            raise CollectorError(f"{settings.where}.repos: at least one repository is required")

    def collect(self) -> list[Evidence]:
        if self.api is not None:
            return self._collect_api(self.api)
        return self._collect_files()

    # -- file mode ---------------------------------------------------------------------
    def _collect_files(self) -> list[Evidence]:
        evidence: list[Evidence] = []
        for spec in self.repos:
            assert spec.branch is not None
            at = self.collected_at()
            if spec.protection_unprotected:
                raw, origin = None, "(not protected)"
            else:
                assert spec.protection_file is not None
                raw = _load_json(spec.protection_file)
                origin = self.relpath(spec.protection_file)
            evidence.append(self._protection_evidence(spec.repo, spec.branch, raw, origin, at))
            if spec.codeowners_file is None:
                text, path, origin = None, None, "(no CODEOWNERS)"
            elif spec.codeowners_file.is_file():
                text = read_text(spec.codeowners_file)
                path, origin = spec.codeowners_location, self.relpath(spec.codeowners_file)
            else:
                raise CollectorError(f"{spec.where}.codeowners: {spec.codeowners_file} not found")
            evidence.append(self._codeowners_evidence(spec.repo, text, path, origin, at))
        return evidence

    # -- api mode ----------------------------------------------------------------------
    def _collect_api(self, api: Settings) -> list[Evidence]:
        base = api.text("base_url", "https://api.github.com").rstrip("/")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "controlmap",
        }
        token_env = api.optional_text("token_env")
        if token_env:
            token = self.context.environ.get(token_env)
            if not token:
                raise CollectorError(f"{api.where}.token_env: {token_env} is not set")
            headers["Authorization"] = f"Bearer {token}"
        transport = self.context.transport_factory()
        evidence: list[Evidence] = []
        for spec in self.repos:
            repo_path = "/".join(urllib.parse.quote(p, safe="") for p in spec.repo.split("/"))
            at = self.collected_at()
            branch = spec.branch
            if branch is None:
                info = transport.get(f"{base}/repos/{repo_path}", headers)
                _expect_ok(info.status, f"repository {spec.repo}")
                branch = str(info.json().get("default_branch") or "")
                if not branch:
                    raise CollectorError(f"repository {spec.repo}: no default_branch in response")
            quoted_branch = urllib.parse.quote(branch, safe="")
            url = f"{base}/repos/{repo_path}/branches/{quoted_branch}/protection"
            response = transport.get(url, headers)
            if response.status == 404:
                raw = None
            else:
                _expect_ok(response.status, f"branch protection for {spec.repo}@{branch}")
                raw = response.json()
            evidence.append(self._protection_evidence(spec.repo, branch, raw, url, at))
            text, found_path, origin = None, None, "(no CODEOWNERS)"
            for location in CODEOWNERS_LOCATIONS:
                url = f"{base}/repos/{repo_path}/contents/{location}?ref={quoted_branch}"
                response = transport.get(url, headers)
                if response.status == 404:
                    continue
                _expect_ok(response.status, f"{location} in {spec.repo}")
                text, found_path, origin = _decode_content(response.json()), location, url
                break
            evidence.append(self._codeowners_evidence(spec.repo, text, found_path, origin, at))
        return evidence

    # -- shared ------------------------------------------------------------------------
    def _protection_evidence(
        self, repo: str, branch: str, raw: Any, origin: str, at: datetime
    ) -> Evidence:
        try:
            data = normalize_protection(raw)
        except CollectorError as exc:
            raise CollectorError(f"{repo}@{branch}: {exc}") from exc
        data["repo"], data["branch"] = repo, branch
        return self.evidence("github.branch_protection", f"{repo}@{branch}", data, origin, at)

    def _codeowners_evidence(
        self, repo: str, text: str | None, path: str | None, origin: str, at: datetime
    ) -> Evidence:
        data = normalize_codeowners(text, path)
        data["repo"] = repo
        return self.evidence("github.codeowners", repo, data, origin, at)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise CollectorError(f"{path}: invalid JSON: {exc}") from exc


def _expect_ok(status: int, what: str) -> None:
    if status in (401, 403):
        raise CollectorError(f"{what}: HTTP {status} (token missing or lacks admin read scope)")
    if not 200 <= status < 300:
        raise CollectorError(f"{what}: unexpected HTTP {status}")


def _decode_content(payload: Any) -> str:
    if not isinstance(payload, Mapping) or payload.get("encoding") != "base64":
        raise CollectorError("contents API response is not a base64-encoded file")
    try:
        # GitHub wraps base64 at 60 columns; strip whitespace, then decode strictly.
        compact = "".join(str(payload.get("content", "")).split())
        return base64.b64decode(compact, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise CollectorError(f"cannot decode file contents: {exc}") from exc
