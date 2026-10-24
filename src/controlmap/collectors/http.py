"""Minimal HTTP transport abstraction so API-backed collectors can be tested offline."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..errors import CollectorError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise CollectorError(f"response is not JSON: {exc}") from exc


class Transport(Protocol):
    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse: ...


class UrllibTransport:
    """Stdlib HTTP(S) transport. Non-2xx statuses are returned, not raised."""

    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        if not url.startswith(("https://", "http://")):
            raise CollectorError(f"refusing non-HTTP URL {url!r}")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
        log.debug("GET %s", url)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return HttpResponse(
                    status=int(response.status),
                    body=response.read(),
                    headers={k.lower(): v for k, v in response.headers.items()},
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status=exc.code,
                body=exc.read() or b"",
                headers={k.lower(): v for k, v in exc.headers.items()},
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CollectorError(f"GET {url} failed: {exc}") from exc
