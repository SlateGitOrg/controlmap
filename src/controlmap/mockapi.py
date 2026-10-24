"""A small, offline mock of the GitHub REST endpoints the ``github`` collector reads.

It exists so that API mode can be demonstrated and integration-tested without network access
or a real organisation. The same routing logic is exposed two ways:

* :class:`MockGitHubTransport` — an in-process :class:`~controlmap.collectors.http.Transport`;
* :func:`serve` — a real HTTP server on localhost (``controlmap mock-github``).

Fixture format (YAML or JSON)::

    token: test-token            # optional; when set, requests need "Authorization: Bearer ..."
    repos:
      acme/api:
        default_branch: main
        branches:
          main: {required_pull_request_reviews: {...}, enforce_admins: {enabled: true}}
          legacy: null           # null = branch exists but is not protected (HTTP 404)
        files:
          .github/CODEOWNERS: "* @acme/eng\\n"

Only GET is supported and only these routes respond::

    /repos/{owner}/{repo}
    /repos/{owner}/{repo}/branches/{branch}/protection
    /repos/{owner}/{repo}/contents/{path}?ref={branch}
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .collectors.http import HttpResponse
from .errors import ConfigError
from .settings import Settings, load_yaml

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class MockRepo:
    default_branch: str
    branches: Mapping[str, Mapping[str, Any] | None]
    files: Mapping[str, str]


@dataclass(frozen=True)
class MockGitHub:
    """The fixture state plus the request router."""

    repos: Mapping[str, MockRepo]
    token: str | None = None

    @classmethod
    def from_file(cls, path: Path) -> MockGitHub:
        return cls.from_settings(Settings(load_yaml(path, ConfigError), path.name, ConfigError))

    @classmethod
    def from_settings(cls, doc: Settings) -> MockGitHub:
        doc.reject_unknown({"token", "repos"})
        repos: dict[str, MockRepo] = {}
        raw_repos = doc.raw("repos")
        raw_repos = {} if raw_repos is None else raw_repos
        if not isinstance(raw_repos, Mapping):
            raise ConfigError(f"{doc.where}.repos: expected a mapping of owner/name to repo")
        for name in raw_repos:
            spec = Settings(raw_repos[name] or {}, f"{doc.where}.repos.{name}", ConfigError)
            spec.reject_unknown({"default_branch", "branches", "files"})
            branches = spec.raw("branches", {})
            files = spec.raw("files", {})
            if not isinstance(branches, Mapping) or not isinstance(files, Mapping):
                raise ConfigError(f"{spec.where}: branches and files must be mappings")
            repos[str(name)] = MockRepo(
                default_branch=spec.text("default_branch", "main"),
                branches={
                    str(b): (dict(p) if p is not None else None) for b, p in branches.items()
                },
                files={str(k): str(v) for k, v in files.items()},
            )
        return cls(repos, doc.optional_text("token"))

    def handle(self, raw_path: str, headers: Mapping[str, str]) -> HttpResponse:
        """Route one GET request (path plus optional query string)."""
        if self.token is not None:
            auth = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
            if auth != f"Bearer {self.token}":
                return _json(401, {"message": "Requires authentication"})
        parsed = urllib.parse.urlsplit(raw_path)
        parts = [urllib.parse.unquote(p) for p in parsed.path.strip("/").split("/")]
        if len(parts) < 3 or parts[0] != "repos":
            return _json(404, {"message": "Not Found"})
        repo_name = f"{parts[1]}/{parts[2]}"
        repo = self.repos.get(repo_name)
        if repo is None:
            return _json(404, {"message": "Not Found"})
        rest = parts[3:]
        if not rest:
            return _json(200, {"full_name": repo_name, "default_branch": repo.default_branch})
        if len(rest) == 3 and rest[0] == "branches" and rest[2] == "protection":
            if rest[1] not in repo.branches:
                return _json(404, {"message": "Branch not found"})
            protection = repo.branches[rest[1]]
            if protection is None:
                return _json(404, {"message": "Branch not protected"})
            return _json(200, protection)
        if rest[0] == "contents" and len(rest) > 1:
            file_path = "/".join(rest[1:])
            if file_path not in repo.files:
                return _json(404, {"message": "Not Found"})
            content = base64.b64encode(repo.files[file_path].encode("utf-8")).decode("ascii")
            return _json(
                200,
                {"type": "file", "path": file_path, "encoding": "base64", "content": content},
            )
        return _json(404, {"message": "Not Found"})


def _json(status: int, payload: Any) -> HttpResponse:
    return HttpResponse(
        status, json.dumps(payload).encode("utf-8"), {"content-type": "application/json"}
    )


class MockGitHubTransport:
    """In-process transport answering requests from a :class:`MockGitHub`."""

    def __init__(self, mock: MockGitHub) -> None:
        self.mock = mock
        self.requests: list[str] = []

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        self.requests.append(path)
        return self.mock.handle(path, headers)


def _handler_for(mock: MockGitHub) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "controlmap-mock-github/1"

        def do_GET(self) -> None:
            response = mock.handle(self.path, dict(self.headers.items()))
            self.send_response(response.status)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.send_header("content-length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)

        def log_message(self, format: str, *args: Any) -> None:
            log.debug("mock-github: " + format, *args)

    return Handler


def serve(mock: MockGitHub, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Create (but do not start) a server; ``port=0`` picks a free port."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("the mock API only binds to a loopback address")
    return ThreadingHTTPServer((host, port), _handler_for(mock))


class BackgroundServer:
    """Context manager running :func:`serve` on a daemon thread; exposes ``base_url``."""

    def __init__(self, mock: MockGitHub, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = serve(mock, host, port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host!s}:{port}"

    def __enter__(self) -> BackgroundServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
