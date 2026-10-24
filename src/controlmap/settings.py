"""Typed access to YAML-decoded mappings with precise error locations.

Configuration, the control library and the exception register are all user-written YAML.
:class:`Settings` wraps one mapping and reports problems as ``<where>.<key>: <problem>`` so
that a mistake in a 300-line library points straight at the offending entry.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from .errors import ControlmapError
from .timeutil import parse_date, parse_datetime

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(text: str, environ: Mapping[str, str] | None = None) -> str:
    """Expand ``${VAR}`` and ``${VAR:-default}``. Unset variables without defaults are errors."""
    env = os.environ if environ is None else environ

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        raise ControlmapError(f"environment variable {name} is not set")

    return _ENV_PATTERN.sub(replace, text)


def load_yaml(path: Path, error: type[ControlmapError]) -> Any:
    """Read a YAML file with the safe loader, mapping I/O and syntax errors to ``error``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise error(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise error(f"{path}: invalid YAML: {exc}") from exc


class Settings:
    """A read-only view over one mapping, with typed getters."""

    def __init__(
        self,
        data: object,
        where: str,
        error: type[ControlmapError] = ControlmapError,
        base_dir: Path | None = None,
    ) -> None:
        if not isinstance(data, Mapping):
            raise error(f"{where}: expected a mapping, got {type(data).__name__}")
        self.data: Mapping[str, Any] = data
        self.where = where
        self.error = error
        self.base_dir = base_dir

    def _fail(self, key: str, problem: str) -> ControlmapError:
        return self.error(f"{self.where}.{key}: {problem}")

    def has(self, key: str) -> bool:
        return key in self.data and self.data[key] is not None

    def raw(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def require(self, key: str) -> Any:
        if not self.has(key):
            raise self.error(f"{self.where}: missing required key '{key}'")
        return self.data[key]

    def text(self, key: str, default: str | None = None) -> str:
        if not self.has(key):
            if default is not None:
                return default
            raise self.error(f"{self.where}: missing required key '{key}'")
        value = self.data[key]
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise self._fail(key, f"expected a string, got {type(value).__name__}")
        text = str(value).strip()
        if not text:
            raise self._fail(key, "must not be empty")
        try:
            return expand_env(text)
        except ControlmapError as exc:
            raise self._fail(key, str(exc)) from exc

    def optional_text(self, key: str) -> str | None:
        return self.text(key) if self.has(key) else None

    def integer(self, key: str, default: int | None = None, minimum: int | None = None) -> int:
        if not self.has(key):
            if default is not None:
                return default
            raise self.error(f"{self.where}: missing required key '{key}'")
        value = self.data[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise self._fail(key, f"expected an integer, got {value!r}")
        if minimum is not None and value < minimum:
            raise self._fail(key, f"must be >= {minimum}, got {value}")
        return value

    def flag(self, key: str, default: bool) -> bool:
        if not self.has(key):
            return default
        value = self.data[key]
        if not isinstance(value, bool):
            raise self._fail(key, f"expected true/false, got {value!r}")
        return value

    def text_list(self, key: str, default: list[str] | None = None) -> list[str]:
        if not self.has(key):
            if default is not None:
                return list(default)
            raise self.error(f"{self.where}: missing required key '{key}'")
        value = self.data[key]
        if isinstance(value, str):
            return [value]
        if not isinstance(value, list) or not all(
            isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in value
        ):
            raise self._fail(key, "expected a list of strings")
        return [str(v) for v in value]

    def mapping(self, key: str) -> Settings:
        return Settings(self.data.get(key) or {}, f"{self.where}.{key}", self.error, self.base_dir)

    def items(self, key: str) -> list[Settings]:
        value = self.data.get(key) or []
        if not isinstance(value, list):
            raise self._fail(key, "expected a list")
        return [
            Settings(item, f"{self.where}.{key}[{i}]", self.error, self.base_dir)
            for i, item in enumerate(value)
        ]

    def timestamp(self, key: str) -> datetime:
        try:
            return parse_datetime(self.require(key), field=f"{self.where}.{key}")
        except ControlmapError as exc:
            raise self.error(str(exc)) from exc

    def optional_timestamp(self, key: str) -> datetime | None:
        return self.timestamp(key) if self.has(key) else None

    def day(self, key: str) -> date:
        try:
            return parse_date(self.require(key), field=f"{self.where}.{key}")
        except ControlmapError as exc:
            raise self.error(str(exc)) from exc

    def optional_day(self, key: str) -> date | None:
        return self.day(key) if self.has(key) else None

    def path(self, key: str) -> Path:
        """A path relative to ``base_dir`` (the directory of the YAML file)."""
        candidate = Path(self.text(key))
        if not candidate.is_absolute() and self.base_dir is not None:
            candidate = self.base_dir / candidate
        return candidate

    def optional_path(self, key: str) -> Path | None:
        return self.path(key) if self.has(key) else None

    def reject_unknown(self, allowed: set[str] | frozenset[str]) -> None:
        unknown = sorted(set(self.data) - set(allowed))
        if unknown:
            raise self.error(
                f"{self.where}: unknown key(s) {', '.join(unknown)}; "
                f"allowed: {', '.join(sorted(allowed))}"
            )
