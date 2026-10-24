"""Framework catalogs, control library validation and the rule registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from controlmap.errors import LibraryError, RuleError
from controlmap.frameworks import load_catalogs, normalize_iso_id, tsc_sort_key
from controlmap.library import load_library, parse_library
from controlmap.model import Finding
from controlmap.rules import Param, RuleOutcome, get_rule, rule, rule_registry
from controlmap.settings import Settings

from .conftest import ACME

CATALOGS = load_catalogs()


def library(controls: list[dict[str, Any]], **doc: Any) -> Any:
    return parse_library(Settings({"controls": controls, **doc}, "lib", LibraryError), CATALOGS)


def control(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "AC-01",
        "title": "MFA",
        "tsc": ["CC6.1"],
        "iso27001": ["A.8.5"],
        "rules": [{"rule": "idp.mfa_enforced"}],
    }
    data.update(over)
    return data


def test_catalogs_are_complete() -> None:
    assert len(CATALOGS.iso) == 93  # ISO/IEC 27001:2022 Annex A has 93 controls
    themes = {c.theme for c in CATALOGS.iso.values()}
    assert themes == {"organizational", "people", "physical", "technological"}
    assert sum(1 for c in CATALOGS.iso.values() if c.theme == "organizational") == 37
    assert sum(1 for c in CATALOGS.tsc.values() if c.category == "security") == 33
    assert CATALOGS.tsc["CC1.3"].label == "Structures, reporting lines and authority"
    assert normalize_iso_id(" a8.5 ") == "8.5"
    assert normalize_iso_id("A.5.1") == "5.1"
    assert sorted(["PI1.1", "A1.2", "CC10.1", "CC2.1", "P1.1", "X"], key=tsc_sort_key) == [
        "CC2.1",
        "CC10.1",
        "A1.2",
        "PI1.1",
        "P1.1",
        "X",
    ]


def test_acme_library_loads() -> None:
    lib = load_library(ACME / "library" / "controls.yaml")
    assert len(lib.controls) == 22
    assert lib.tsc_categories == ("security", "availability", "confidentiality")
    ep01 = lib.control("EP-01")
    assert ep01.rules[0].freshness_days == 7
    bc01 = lib.control("BC-01")
    assert [r.freshness_days for r in bc01.rules] == [35, 400]
    assert lib.control("RA-01").iso == ()
    assert lib.warnings == ()
    with pytest.raises(KeyError):
        lib.control("ZZ-99")


def test_parse_normalizes_and_sorts_mappings() -> None:
    lib = library([control(tsc=["CC6.6", "CC6.1", "CC6.1"], iso27001=["8.20", "A.5.15", "A8.5"])])
    parsed = lib.controls[0]
    assert parsed.tsc == ("CC6.1", "CC6.6")
    assert parsed.iso == ("5.15", "8.5", "8.20")
    assert parsed.owner == "unassigned"
    assert parsed.rules[0].params == {"include_service_accounts": False, "disallowed_factors": []}


@pytest.mark.parametrize(
    ("controls", "doc", "message"),
    [
        ([], {}, "defines no controls"),
        ([control(), control()], {}, "duplicate control id AC-01"),
        ([control(id="ac1")], {}, "must look like 'AC-01'"),
        ([control(tsc=["CC6.9"])], {}, "unknown TSC criteria CC6.9"),
        ([control(tsc=[])], {}, "at least one TSC criterion"),
        ([control(iso27001=["A.8.35"])], {}, "unknown ISO 27001:2022 Annex A controls 8.35"),
        ([control(rules=[])], {}, "at least one rule"),
        ([control(rules=[{"rule": "nope.rule"}])], {}, "unknown rule 'nope.rule'"),
        (
            [control(rules=[{"rule": "idp.mfa_enforced", "params": {"x": 1}}])],
            {},
            "unknown parameter",
        ),
        (
            [
                control(
                    rules=[
                        {"rule": "idp.inactive_accounts", "params": {"max_days_since_login": "90"}}
                    ]
                )
            ],
            {},
            "must be int",
        ),
        (
            [
                control(
                    rules=[
                        {"rule": "idp.inactive_accounts", "params": {"max_days_since_login": True}}
                    ]
                )
            ],
            {},
            "got a boolean",
        ),
        ([control(rules=[{"rule": "idp.mfa_enforced", "freshness_days": 0}])], {}, ">= 1"),
        ([control(colour="red")], {}, "unknown key"),
        ([control()], {"version": 2}, "unsupported library version"),
        (
            [control()],
            {"scope": {"tsc_categories": ["security", "magic"]}},
            "unknown TSC categories",
        ),
    ],
)
def test_library_validation_errors(
    controls: list[dict[str, Any]], doc: dict[str, Any], message: str
) -> None:
    with pytest.raises(LibraryError, match=message):
        library(controls, **doc)


def test_out_of_scope_mapping_is_a_warning() -> None:
    lib = library([control(tsc=["CC6.1", "P4.1"])])
    assert lib.warnings == ("AC-01 maps to out-of-scope criteria P4.1",)


def test_rule_registry_contents_and_custom_rules() -> None:
    names = {name for name in rule_registry() if not name.startswith("test.")}
    assert len(names) == 22
    assert {
        "github.branch_protection",
        "cloud.kms_rotation",
        "endpoint.inventory_reconciled",
    } <= names
    with pytest.raises(RuleError, match="unknown rule"):
        get_rule("missing")

    @rule("test.always_fails", description="test", requires=("k",), params=[Param("n", "int", 1)])
    def always_fails(ctx: Any) -> RuleOutcome:
        return RuleOutcome(ctx.param("n"), [Finding("r", "bad")])

    spec = get_rule("test.always_fails")
    assert spec.required_kinds({}) == ("k",)
    assert spec.resolve_params({"n": 3}, "w") == {"n": 3}
    with pytest.raises(ValueError, match="already registered"):
        rule("test.always_fails", description="dup", requires=())(lambda ctx: RuleOutcome(0))
    with pytest.raises(ValueError, match="unknown type"):
        rule("test.bad_param", description="x", requires=(), params=[Param("p", "float")])(
            lambda ctx: RuleOutcome(0)
        )


def test_library_file_errors(tmp_path: Path) -> None:
    with pytest.raises(LibraryError, match="cannot read"):
        load_library(tmp_path / "missing.yaml")
