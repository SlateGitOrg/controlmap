"""Rule plugin interface and registry.

A rule is a pure function from a :class:`RuleContext` (point-in-time evidence plus validated
parameters) to a :class:`RuleOutcome` (how many items it checked and which ones deviate).
Rules never decide freshness or exceptions: the engine owns those, so every rule gets the same
semantics for free.

Third-party rules can be registered from the ``controlmap.rules`` entry-point group; each entry
point must resolve to a module that calls :func:`rule` at import time.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from importlib.metadata import entry_points
from typing import Any

from ..errors import RuleError
from ..model import Evidence, Finding

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "controlmap.rules"

ParamValue = int | bool | str | list[Any] | dict[str, Any]
_PARAM_TYPES: dict[str, type | tuple[type, ...]] = {
    "int": int,
    "bool": bool,
    "str": str,
    "list": list,
    "dict": dict,
}


@dataclass(frozen=True)
class Param:
    """A declared rule parameter. ``default=None`` with ``required=True`` means no default."""

    name: str
    type: str
    default: Any = None
    help: str = ""
    required: bool = False

    def coerce(self, value: Any, where: str) -> Any:
        expected = _PARAM_TYPES[self.type]
        if isinstance(value, bool) and self.type == "int":
            raise RuleError(f"{where}: parameter {self.name} must be an int, got a boolean")
        if not isinstance(value, expected):
            raise RuleError(
                f"{where}: parameter {self.name} must be {self.type}, got {type(value).__name__}"
            )
        return value


@dataclass(frozen=True)
class RuleOutcome:
    """What a rule observed: population size, deviations and free-text notes.

    ``used`` lists the evidence records the verdict rests on when that is a subset of what the
    rule was given (e.g. only the latest of several documents). The engine judges freshness and
    cites evidence only over these. ``None`` means every record the rule was given.
    """

    checked: int
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    used: list[Evidence] | None = None


class RuleContext:
    """Evidence and parameters available to one rule invocation."""

    def __init__(
        self,
        as_of: date,
        params: Mapping[str, Any],
        evidence: Mapping[str, Sequence[Evidence]],
    ) -> None:
        self.as_of = as_of
        self.params = params
        self._evidence = evidence

    def records(self, kind: str) -> list[Evidence]:
        """All selected evidence records of ``kind`` (one per subject), sorted by subject."""
        return sorted(self._evidence.get(kind, ()), key=lambda e: e.subject)

    def items(self, kind: str, key: str) -> list[tuple[Evidence, dict[str, Any]]]:
        """Flatten the list ``data[key]`` across every record of ``kind``."""
        out: list[tuple[Evidence, dict[str, Any]]] = []
        for record in self.records(kind):
            values = record.data.get(key)
            if not isinstance(values, list):
                raise RuleError(f"{kind} evidence from {record.subject} has no list '{key}'")
            out.extend((record, item) for item in values)
        return out

    def param(self, name: str) -> Any:
        return self.params[name]


RuleFunc = Callable[[RuleContext], RuleOutcome]
Requires = tuple[str, ...] | Callable[[Mapping[str, Any]], tuple[str, ...]]


@dataclass(frozen=True)
class RuleSpec:
    name: str
    description: str
    func: RuleFunc
    requires: Requires
    params: tuple[Param, ...] = ()
    optional: tuple[str, ...] = ()

    def required_kinds(self, params: Mapping[str, Any]) -> tuple[str, ...]:
        return self.requires(params) if callable(self.requires) else self.requires

    def resolve_params(self, given: Mapping[str, Any] | None, where: str) -> dict[str, Any]:
        """Validate user parameters against the declaration and fill in defaults."""
        given = dict(given or {})
        declared = {p.name: p for p in self.params}
        unknown = sorted(set(given) - set(declared))
        if unknown:
            allowed = ", ".join(sorted(declared)) or "none"
            raise RuleError(
                f"{where}: unknown parameter(s) {', '.join(unknown)} for rule {self.name} "
                f"(allowed: {allowed})"
            )
        resolved: dict[str, Any] = {}
        for name, param in declared.items():
            if name in given:
                resolved[name] = param.coerce(given[name], where)
            elif param.required:
                raise RuleError(f"{where}: rule {self.name} requires parameter {name}")
            else:
                resolved[name] = param.default
        return resolved


_REGISTRY: dict[str, RuleSpec] = {}


def rule(
    name: str,
    *,
    description: str,
    requires: Requires,
    params: Sequence[Param] = (),
    optional: Sequence[str] = (),
) -> Callable[[RuleFunc], RuleFunc]:
    """Decorator registering a rule function under ``name``."""

    def decorate(func: RuleFunc) -> RuleFunc:
        if name in _REGISTRY and _REGISTRY[name].func is not func:
            raise ValueError(f"rule {name!r} is already registered")
        for param in params:
            if param.type not in _PARAM_TYPES:
                raise ValueError(f"rule {name}: parameter {param.name} has unknown type")
        _REGISTRY[name] = RuleSpec(
            name, description, func, requires, tuple(params), tuple(optional)
        )
        return func

    return decorate


@cache
def _load_entry_points() -> None:
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            ep.load()
        except Exception as exc:  # a broken plugin must not take down the built-ins
            log.warning("could not load rule plugin %s: %s", ep.name, exc)


def rule_registry() -> dict[str, RuleSpec]:
    _load_entry_points()
    return dict(sorted(_REGISTRY.items()))


def get_rule(name: str) -> RuleSpec:
    registry = rule_registry()
    if name not in registry:
        raise RuleError(f"unknown rule {name!r}")
    return registry[name]


def days_between(earlier: date, later: date) -> int:
    return (later - earlier).days


def as_date(value: Any, what: str) -> date | None:
    """Evidence stores dates as ISO strings once round-tripped through JSON."""
    if value is None or value == "":
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError as exc:
        raise RuleError(f"{what}: not a date: {value!r}") from exc
