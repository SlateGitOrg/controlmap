"""The control library: company controls mapped to TSC criteria and ISO Annex A controls.

A library is a YAML document::

    version: 1
    scope:
      tsc_categories: [security, availability, confidentiality]
    defaults:
      freshness_days: 35          # evidence older than this is STALE
    controls:
      - id: AC-01
        title: MFA for workforce identities
        description: ...
        owner: IT
        tsc: [CC6.1]
        iso27001: ["5.17", "8.5"]
        freshness_days: 35        # optional per-control override
        rules:
          - rule: idp.mfa_enforced
            params: {disallowed_factors: [sms]}
            freshness_days: 7     # optional per-rule override

Loading validates everything up front: control ids are unique, every criterion and Annex A
reference exists in the bundled catalogs, every rule exists and every parameter type-checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import LibraryError, RuleError
from .frameworks import Catalogs, iso_sort_key, load_catalogs, normalize_iso_id, tsc_sort_key
from .rules import RuleSpec, get_rule
from .settings import Settings, load_yaml

_CONTROL_ID = re.compile(r"^[A-Z][A-Z0-9]*-[0-9]{2,3}$")
CONTROL_KEYS = frozenset(
    {"id", "title", "description", "owner", "tsc", "iso27001", "freshness_days", "rules"}
)
RULE_KEYS = frozenset({"rule", "params", "freshness_days"})
DEFAULT_SCOPE = ["security", "availability", "confidentiality"]


@dataclass(frozen=True)
class ControlRule:
    spec: RuleSpec
    params: dict[str, Any]
    freshness_days: int

    @property
    def name(self) -> str:
        return self.spec.name

    def required_kinds(self) -> tuple[str, ...]:
        return self.spec.required_kinds(self.params)


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    description: str
    owner: str
    tsc: tuple[str, ...]
    iso: tuple[str, ...]
    rules: tuple[ControlRule, ...]


@dataclass(frozen=True)
class Library:
    controls: tuple[Control, ...]
    catalogs: Catalogs
    tsc_categories: tuple[str, ...]
    source: str = ""
    warnings: tuple[str, ...] = field(default=())

    def control(self, control_id: str) -> Control:
        for control in self.controls:
            if control.id == control_id:
                return control
        raise KeyError(control_id)

    @property
    def control_ids(self) -> set[str]:
        return {c.id for c in self.controls}


def load_library(path: Path, catalogs: Catalogs | None = None) -> Library:
    catalogs = catalogs or load_catalogs()
    doc = Settings(load_yaml(path, LibraryError), path.name, LibraryError, path.parent)
    return parse_library(doc, catalogs, source=path.name)


def parse_library(doc: Settings, catalogs: Catalogs, source: str = "") -> Library:
    doc.reject_unknown({"version", "scope", "defaults", "controls"})
    if doc.integer("version", 1) != 1:
        raise LibraryError(f"{doc.where}: unsupported library version {doc.raw('version')}")
    scope = doc.mapping("scope")
    scope.reject_unknown({"tsc_categories"})
    categories = scope.text_list("tsc_categories", DEFAULT_SCOPE)
    unknown_categories = sorted(set(categories) - set(catalogs.tsc_categories))
    if unknown_categories:
        raise LibraryError(f"{scope.where}: unknown TSC categories {unknown_categories}")
    defaults = doc.mapping("defaults")
    defaults.reject_unknown({"freshness_days"})
    default_freshness = defaults.integer("freshness_days", 35, minimum=1)

    controls: list[Control] = []
    seen: set[str] = set()
    warnings: list[str] = []
    for entry in doc.items("controls"):
        control = _parse_control(entry, catalogs, default_freshness)
        if control.id in seen:
            raise LibraryError(f"{entry.where}: duplicate control id {control.id}")
        seen.add(control.id)
        out_of_scope = [c for c in control.tsc if catalogs.tsc[c].category not in categories]
        if out_of_scope:
            warnings.append(f"{control.id} maps to out-of-scope criteria {', '.join(out_of_scope)}")
        controls.append(control)
    if not controls:
        raise LibraryError(f"{doc.where}: the library defines no controls")
    return Library(
        tuple(sorted(controls, key=lambda c: c.id)),
        catalogs,
        tuple(categories),
        source,
        tuple(warnings),
    )


def _parse_control(entry: Settings, catalogs: Catalogs, default_freshness: int) -> Control:
    entry.reject_unknown(CONTROL_KEYS)
    control_id = entry.text("id")
    if not _CONTROL_ID.match(control_id):
        raise LibraryError(f"{entry.where}.id: {control_id!r} must look like 'AC-01'")
    where = f"control {control_id}"
    tsc = sorted(set(entry.text_list("tsc", [])), key=tsc_sort_key)
    bad_tsc = [c for c in tsc if c not in catalogs.tsc]
    if bad_tsc:
        raise LibraryError(f"{where}: unknown TSC criteria {', '.join(bad_tsc)}")
    iso = sorted({normalize_iso_id(i) for i in entry.text_list("iso27001", [])}, key=_iso_key)
    bad_iso = [i for i in iso if i not in catalogs.iso]
    if bad_iso:
        raise LibraryError(f"{where}: unknown ISO 27001:2022 Annex A controls {', '.join(bad_iso)}")
    if not tsc:
        raise LibraryError(f"{where}: must map to at least one TSC criterion")
    freshness = entry.integer("freshness_days", default_freshness, minimum=1)
    rules = []
    for rule_entry in entry.items("rules"):
        rule_entry.reject_unknown(RULE_KEYS)
        name = rule_entry.text("rule")
        try:
            spec = get_rule(name)
            params = spec.resolve_params(rule_entry.mapping("params").data, f"{where} rule {name}")
        except RuleError as exc:
            raise LibraryError(f"{where}: {exc}") from exc
        rules.append(
            ControlRule(spec, params, rule_entry.integer("freshness_days", freshness, minimum=1))
        )
    if not rules:
        raise LibraryError(f"{where}: must declare at least one rule")
    return Control(
        id=control_id,
        title=entry.text("title"),
        description=entry.text("description", ""),
        owner=entry.text("owner", "unassigned"),
        tsc=tuple(tsc),
        iso=tuple(iso),
        rules=tuple(rules),
    )


def _iso_key(control_id: str) -> tuple[int, ...]:
    try:
        return iso_sort_key(control_id)
    except ValueError:
        return (999,)
