"""GitHub collector in file mode and API mode (against the in-process mock)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from controlmap.collectors.http import HttpResponse
from controlmap.errors import CollectorError, ConfigError
from controlmap.mockapi import MockGitHub, MockGitHubTransport

from .conftest import ACME
from .helpers import make_collector, write

MOCK = MockGitHub.from_file(ACME / "data" / "mock-github.yaml")
TOKEN_ENV = {"GH_TOKEN": "mock-token-not-a-secret"}


def file_collector(tmp_path: Path, repos: list[dict[str, Any]]) -> Any:
    return make_collector({"name": "gh", "type": "github", "repos": repos}, tmp_path)


def test_file_mode_reads_saved_responses(tmp_path: Path) -> None:
    write(tmp_path / "p.json", (ACME / "data/github/api.main.protection.json").read_text())
    write(tmp_path / "CODEOWNERS", "* @o/eng\n")
    collector = file_collector(
        tmp_path,
        [
            {"repo": "o/a", "branch": "main", "protection": "p.json", "codeowners": "CODEOWNERS"},
            {"repo": "o/b", "branch": "dev", "protection": None},
        ],
    )
    records = collector.collect()
    assert [(r.kind, r.subject) for r in records] == [
        ("github.branch_protection", "o/a@main"),
        ("github.codeowners", "o/a"),
        ("github.branch_protection", "o/b@dev"),
        ("github.codeowners", "o/b"),
    ]
    a = records[0].data
    assert a["required_approvals"] == 2
    assert a["required_status_checks"] == ["ci/lint", "ci/test"]
    assert a["enforce_admins"] and not a["allow_force_pushes"]
    assert records[1].data["found"] and records[1].data["rules"][0]["owners"] == ["@o/eng"]
    assert records[2].data["protected"] is False
    assert records[2].origin == "(not protected)"
    assert records[3].data == {
        "found": False,
        "path": None,
        "rules": [],
        "issues": [],
        "repo": "o/b",
    }


@pytest.mark.parametrize(
    ("repos", "message"),
    [
        ([], "at least one repository"),
        ([{"repo": "noslash", "branch": "m", "protection": None}], "owner/name"),
        ([{"repo": "o/r", "protection": None}], "'branch' is required"),
        ([{"repo": "o/r", "branch": "m"}], "'protection' is required"),
        ([{"repo": "o/r", "branch": "m", "protection": None, "colour": 1}], "unknown key"),
    ],
)
def test_file_mode_config_errors(tmp_path: Path, repos: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        file_collector(tmp_path, repos)


def test_file_mode_data_errors(tmp_path: Path) -> None:
    write(tmp_path / "bad.json", "{")
    write(tmp_path / "list.json", "[]")
    write(
        tmp_path / "count.json",
        json.dumps({"required_pull_request_reviews": {"required_approving_review_count": "2"}}),
    )
    for name, message in [
        ("bad.json", "invalid JSON"),
        ("list.json", "JSON object"),
        ("count.json", "integer"),
    ]:
        collector = file_collector(tmp_path, [{"repo": "o/r", "branch": "m", "protection": name}])
        with pytest.raises(CollectorError, match=message):
            collector.collect()
    missing = file_collector(
        tmp_path, [{"repo": "o/r", "branch": "m", "protection": None, "codeowners": "nope"}]
    )
    with pytest.raises(CollectorError, match="not found"):
        missing.collect()


def api_collector(
    tmp_path: Path, repos: list[dict[str, Any]], transport: Any, env: dict[str, str] | None = None
) -> Any:
    return make_collector(
        {
            "name": "gh",
            "type": "github",
            "api": {"base_url": "https://mock.invalid/", "token_env": "GH_TOKEN"},
            "repos": repos,
        },
        tmp_path,
        transport_factory=lambda: transport,
        environ=TOKEN_ENV if env is None else env,
    )


def test_api_mode_discovers_default_branch_protection_and_codeowners(tmp_path: Path) -> None:
    transport = MockGitHubTransport(MOCK)
    records = api_collector(
        tmp_path, [{"repo": "acme/api"}, {"repo": "acme/web"}, {"repo": "acme/sandbox"}], transport
    ).collect()
    subjects = [r.subject for r in records]
    assert subjects == [
        "acme/api@main",
        "acme/api",
        "acme/web@main",
        "acme/web",
        "acme/sandbox@trunk",
        "acme/sandbox",
    ]
    api, api_owners, web, web_owners, sandbox, sandbox_owners = (r.data for r in records)
    assert api["required_approvals"] == 2
    assert api_owners["path"] == ".github/CODEOWNERS"
    assert web["enforce_admins"] is False
    assert web_owners["path"] == "CODEOWNERS"  # found at the second location
    assert sandbox["protected"] is False
    assert sandbox_owners["found"] is False
    assert "/repos/acme/api/branches/main/protection" in transport.requests
    assert records[0].origin == "https://mock.invalid/repos/acme/api/branches/main/protection"


def test_api_mode_with_explicit_branch_skips_repo_lookup(tmp_path: Path) -> None:
    transport = MockGitHubTransport(MOCK)
    api_collector(tmp_path, [{"repo": "acme/api", "branch": "main"}], transport).collect()
    assert "/repos/acme/api" not in transport.requests


def test_api_mode_auth_errors(tmp_path: Path) -> None:
    with pytest.raises(CollectorError, match="GH_TOKEN is not set"):
        api_collector(tmp_path, [{"repo": "acme/api"}], MockGitHubTransport(MOCK), env={}).collect()
    with pytest.raises(CollectorError, match="HTTP 401"):
        api_collector(
            tmp_path, [{"repo": "acme/api"}], MockGitHubTransport(MOCK), env={"GH_TOKEN": "wrong"}
        ).collect()


class ScriptedTransport:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses

    def get(self, url: str, headers: Any) -> HttpResponse:
        for suffix, response in self.responses.items():
            if url.endswith(suffix):
                return response
        return HttpResponse(404, b"{}")


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        ({"/repos/o/r": HttpResponse(500, b"")}, "unexpected HTTP 500"),
        ({"/repos/o/r": HttpResponse(200, b"{}")}, "no default_branch"),
        ({"/repos/o/r": HttpResponse(200, b"<html>")}, "not JSON"),
        (
            {
                "/repos/o/r": HttpResponse(200, b'{"default_branch": "main"}'),
                "/protection": HttpResponse(403, b""),
            },
            "HTTP 403",
        ),
        (
            {
                "/repos/o/r": HttpResponse(200, b'{"default_branch": "main"}'),
                "?ref=main": HttpResponse(200, b'{"encoding": "none"}'),
            },
            "not a base64",
        ),
        (
            {
                "/repos/o/r": HttpResponse(200, b'{"default_branch": "main"}'),
                "?ref=main": HttpResponse(200, b'{"encoding": "base64", "content": "@@@"}'),
            },
            "cannot decode",
        ),
    ],
)
def test_api_mode_response_errors(
    tmp_path: Path, responses: dict[str, HttpResponse], message: str
) -> None:
    with pytest.raises(CollectorError, match=message):
        api_collector(tmp_path, [{"repo": "o/r"}], ScriptedTransport(responses)).collect()
