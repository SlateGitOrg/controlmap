"""Shared fixtures and builders for the test suite."""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from controlmap.model import Evidence
from controlmap.rules import RuleContext, RuleOutcome, get_rule

ROOT = Path(__file__).resolve().parent.parent
ACME = ROOT / "examples" / "acme"
AS_OF = date(2026, 10, 1)


def at(day: str, hour: int = 12) -> datetime:
    """A UTC timestamp at ``hour`` on an ISO ``day``."""
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), tzinfo=UTC).replace(
        hour=hour
    )


def ev(
    kind: str,
    data: Mapping[str, Any],
    *,
    subject: str = "subj",
    collected: str = "2026-09-30",
    source: str = "test",
) -> Evidence:
    return Evidence(kind, subject, source, at(collected), dict(data), origin="test")


def run_rule(
    name: str,
    evidence: Sequence[Evidence],
    params: Mapping[str, Any] | None = None,
    as_of: date = AS_OF,
) -> RuleOutcome:
    """Run one registered rule directly, with its parameters resolved like the library does."""
    spec = get_rule(name)
    resolved = spec.resolve_params(params, f"test {name}")
    grouped: dict[str, list[Evidence]] = {}
    for record in evidence:
        grouped.setdefault(record.kind, []).append(record)
    return spec.func(RuleContext(as_of, resolved, grouped))


def resources(outcome: RuleOutcome) -> list[str]:
    return sorted(f.resource for f in outcome.findings)


@pytest.fixture
def acme(tmp_path: Path) -> Path:
    """A private copy of the sample company (without any stored evidence)."""
    target = tmp_path / "acme"
    shutil.copytree(ACME, target, ignore=shutil.ignore_patterns(".controlmap"))
    return target
