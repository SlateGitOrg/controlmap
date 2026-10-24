"""Builders for collector tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from controlmap.collectors import Collector, CollectorContext, build_collector
from controlmap.errors import ConfigError
from controlmap.settings import Settings

FIXED = datetime(2026, 9, 30, 12, tzinfo=UTC)


def make_collector(config: dict[str, Any], base: Path, **context: Any) -> Collector:
    ctx = CollectorContext(base_dir=base, clock=lambda: FIXED, **context)
    return build_collector(Settings(config, "collectors[0]", ConfigError, base), ctx)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_yaml(path: Path, data: Any) -> Path:
    return write(path, yaml.safe_dump(data, sort_keys=False))
