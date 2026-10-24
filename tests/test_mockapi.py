"""The offline GitHub mock, in-process and over a real loopback socket."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from controlmap.collectors.http import UrllibTransport
from controlmap.errors import CollectorError, ConfigError
from controlmap.mockapi import BackgroundServer, MockGitHub, serve
from controlmap.project import collect, load_config
from controlmap.settings import Settings

from .conftest import ACME

MOCK = MockGitHub.from_file(ACME / "data" / "mock-github.yaml")
AUTH = {"Authorization": "Bearer mock-token-not-a-secret"}


def test_routes() -> None:
    assert MOCK.handle("/repos/acme/api", AUTH).json()["default_branch"] == "main"
    assert MOCK.handle("/repos/acme/api/branches/main/protection", AUTH).status == 200
    assert MOCK.handle("/repos/acme/sandbox/branches/trunk/protection", AUTH).json() == {
        "message": "Branch not protected"
    }
    assert MOCK.handle("/repos/acme/api/branches/nope/protection", AUTH).status == 404
    content = MOCK.handle("/repos/acme/api/contents/.github/CODEOWNERS?ref=main", AUTH).json()
    assert base64.b64decode(content["content"]).startswith(b"*  @acme/backend")
    for path in ("/repos/acme/api/contents/NOPE", "/repos/x/y", "/user", "/repos/acme/api/hooks"):
        assert MOCK.handle(path, AUTH).status == 404
    assert MOCK.handle("/repos/acme/api", {}).status == 401


def test_fixture_validation() -> None:
    with pytest.raises(ConfigError, match="unknown key"):
        MockGitHub.from_settings(Settings({"repos": {}, "extra": 1}, "m", ConfigError))
    with pytest.raises(ConfigError, match="mapping of owner/name"):
        MockGitHub.from_settings(Settings({"repos": []}, "m", ConfigError))
    with pytest.raises(ConfigError, match="must be mappings"):
        MockGitHub.from_settings(Settings({"repos": {"a/b": {"files": []}}}, "m", ConfigError))
    open_mock = MockGitHub.from_settings(Settings({"repos": {"a/b": None}}, "m", ConfigError))
    assert open_mock.handle("/repos/a/b", {}).json()["default_branch"] == "main"


def test_server_refuses_non_loopback_binding() -> None:
    with pytest.raises(ConfigError, match="loopback"):
        serve(MOCK, host="0.0.0.0")


def test_api_mode_end_to_end_over_http(acme: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with BackgroundServer(MOCK) as server:
        monkeypatch.setenv("GITHUB_API_URL", server.base_url)
        monkeypatch.setenv("GITHUB_TOKEN", "mock-token-not-a-secret")
        config = load_config(acme / "controlmap.api.yaml")
        report = collect(config)
        assert report.ok, report.collectors
        assert report.collectors[0].records == 6
        subjects = sorted(r.subject for r in config.store())
        assert subjects == [
            "acme/api",
            "acme/api@main",
            "acme/sandbox",
            "acme/sandbox@trunk",
            "acme/web",
            "acme/web@main",
        ]
        response = UrllibTransport(timeout=5).get(f"{server.base_url}/repos/acme/api", {})
        assert response.status == 401


def test_urllib_transport_rejects_other_schemes_and_reports_connection_errors() -> None:
    with pytest.raises(CollectorError, match="refusing non-HTTP"):
        UrllibTransport().get("file:///etc/passwd", {})
    with BackgroundServer(MOCK) as server:
        url = server.base_url
    with pytest.raises(CollectorError, match="failed"):
        UrllibTransport(timeout=2).get(f"{url}/repos/acme/api", {})
