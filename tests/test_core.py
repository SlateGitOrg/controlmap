"""Canonical encoding, time helpers, version comparison, settings and the evidence model."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from controlmap.canonical import canonical_json, pretty_json, sha256_bytes, sha256_file, to_jsonable
from controlmap.errors import ConfigError, ControlmapError, EvidenceError
from controlmap.model import Attachment, Evidence, Status
from controlmap.settings import Settings, expand_env, load_yaml
from controlmap.timeutil import (
    end_of_day,
    isoformat,
    optional_date,
    parse_date,
    parse_datetime,
    utc_now,
)
from controlmap.versions import compare_versions, parse_version

# -- canonical -------------------------------------------------------------------------------
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=5), children, max_size=4)
    ),
    max_leaves=12,
)


@given(_JSON)
def test_canonical_json_round_trips_and_is_stable(value: Any) -> None:
    encoded = canonical_json(value)
    assert json.loads(encoded) == value
    assert canonical_json(json.loads(encoded)) == encoded


@given(st.dictionaries(st.text(max_size=4), st.integers(), max_size=6))
def test_canonical_json_ignores_insertion_order(mapping: dict[str, int]) -> None:
    reordered = dict(reversed(list(mapping.items())))
    assert canonical_json(mapping) == canonical_json(reordered)


def test_to_jsonable_converts_dates_sets_and_tuples() -> None:
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    assert to_jsonable({"t": when, "d": date(2026, 1, 2), "s": {"b", "a"}, "x": (1, 2)}) == {
        "t": "2026-01-02T01:04:05Z",
        "d": "2026-01-02",
        "s": ["a", "b"],
        "x": [1, 2],
    }
    with pytest.raises(TypeError, match="not JSON-serialisable"):
        to_jsonable(object())
    with pytest.raises(ValueError):
        canonical_json(float("nan"))


def test_pretty_json_and_hashing(tmp_path: Path) -> None:
    assert pretty_json({"b": 1, "a": [1]}) == '{\n  "a": [\n    1\n  ],\n  "b": 1\n}\n'
    path = tmp_path / "f"
    path.write_bytes(b"x" * 70_000)
    assert sha256_file(path) == (sha256_bytes(b"x" * 70_000), 70_000)


# -- time ------------------------------------------------------------------------------------
def test_parse_datetime_variants() -> None:
    assert parse_datetime("2026-09-30T10:00:00Z") == datetime(2026, 9, 30, 10, tzinfo=UTC)
    assert parse_datetime("2026-09-30T12:00:00+02:00") == datetime(2026, 9, 30, 10, tzinfo=UTC)
    assert parse_datetime("2026-09-30") == datetime(2026, 9, 30, tzinfo=UTC)
    assert parse_datetime(date(2026, 9, 30)) == datetime(2026, 9, 30, tzinfo=UTC)
    assert parse_datetime(datetime(2026, 9, 30, 1)) == datetime(2026, 9, 30, 1, tzinfo=UTC)
    for bad in ("", "noon", 12):
        with pytest.raises(ControlmapError):
            parse_datetime(bad)


def test_dates_and_formatting() -> None:
    assert parse_date("2026-09-30T23:30:00-02:00") == date(2026, 10, 1)
    assert parse_date(datetime(2026, 9, 30, 5, tzinfo=UTC)) == date(2026, 9, 30)
    assert optional_date("") is None
    assert optional_date(None) is None
    assert end_of_day(date(2026, 1, 1)).isoformat().startswith("2026-01-01T23:59:59.999999")
    assert isoformat(datetime(2026, 1, 1, tzinfo=UTC)) == "2026-01-01T00:00:00Z"


def test_utc_now_honours_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790000000")
    assert utc_now() == datetime.fromtimestamp(1790000000, tz=UTC)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "soon")
    with pytest.raises(ControlmapError, match="SOURCE_DATE_EPOCH"):
        utc_now()
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    assert utc_now().tzinfo is UTC


# -- versions --------------------------------------------------------------------------------
def test_version_parsing_and_comparison() -> None:
    assert parse_version("14.6.1 (23G93)") == (14, 6, 1)
    assert parse_version("v10.0.19045.4529") == (10, 0, 19045, 4529)
    assert compare_versions("14.0", "14") == 0
    assert compare_versions("14.0.1", "14") == 1
    assert compare_versions("13.9", "14.0") == -1
    with pytest.raises(ValueError):
        parse_version("unknown")


_VERSION = st.lists(st.integers(0, 50), min_size=1, max_size=4).map(lambda p: ".".join(map(str, p)))


@given(_VERSION, _VERSION)
def test_version_comparison_is_antisymmetric(a: str, b: str) -> None:
    assert compare_versions(a, b) == -compare_versions(b, a)
    assert compare_versions(a, a) == 0


# -- settings --------------------------------------------------------------------------------
def test_env_expansion() -> None:
    env = {"A": "1"}
    assert expand_env("x${A}y${B:-dflt}", env) == "x1ydflt"
    with pytest.raises(ControlmapError, match="B is not set"):
        expand_env("${B}", env)


def test_settings_typed_getters_and_error_locations(tmp_path: Path) -> None:
    s = Settings(
        {
            "n": 3,
            "b": True,
            "t": " hi ",
            "l": ["a", 1],
            "one": "x",
            "nested": {"k": 1},
            "items": [{"a": 1}],
        },
        "cfg",
        ConfigError,
        tmp_path,
    )
    assert (s.integer("n"), s.flag("b", False), s.text("t")) == (3, True, "hi")
    assert s.text_list("l") == ["a", "1"]
    assert s.text_list("one") == ["x"]
    assert s.mapping("nested").integer("k") == 1
    assert s.items("items")[0].where == "cfg.items[0]"
    assert s.path("t") == tmp_path / "hi"
    assert s.optional_text("missing") is None
    assert s.flag("missing", True) is True
    checks: list[tuple[Callable[[], object], str]] = [
        (lambda: s.integer("b"), "cfg.b: expected an integer"),
        (lambda: s.integer("n", minimum=5), "must be >= 5"),
        (lambda: s.text("nested"), "expected a string"),
        (lambda: s.text("missing"), "missing required key 'missing'"),
        (lambda: s.flag("n", False), "expected true/false"),
        (lambda: s.text_list("nested"), "list of strings"),
        (lambda: s.items("n"), "expected a list"),
        (lambda: s.reject_unknown({"n"}), "unknown key"),
        (lambda: Settings([], "root", ConfigError), "expected a mapping"),
    ]
    for call, message in checks:
        with pytest.raises(ConfigError, match=message):
            call()
    with pytest.raises(ConfigError, match="must not be empty"):
        Settings({"e": "  "}, "x", ConfigError).text("e")


def test_load_yaml_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_yaml(tmp_path / "nope.yaml", ConfigError)
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_yaml(bad, ConfigError)


# -- model -----------------------------------------------------------------------------------
def make(**over: Any) -> Evidence:
    fields: dict[str, Any] = {
        "kind": "k",
        "subject": "s",
        "source": "src",
        "collected_at": datetime(2026, 9, 30, tzinfo=UTC),
        "data": {"when": date(2026, 9, 1), "items": (1, 2)},
        "origin": "a.csv",
    }
    fields.update(over)
    return Evidence(**fields)


def test_evidence_digest_is_content_addressed() -> None:
    record = make()
    assert record.data == {"when": "2026-09-01", "items": [1, 2]}
    assert make(origin="elsewhere.csv").digest == record.digest  # origin is not hashed
    assert make(data={"when": "2026-09-02"}).digest != record.digest
    with_attachment = make(attachments=(Attachment("f.pdf", "ab" * 32, 3, "/x/f.pdf"),))
    assert with_attachment.digest != record.digest
    assert Evidence.from_dict(with_attachment.to_dict()) == with_attachment


def test_evidence_from_dict_detects_tampering_and_malformed_records() -> None:
    record = make().to_dict()
    record["data"]["when"] = "2026-09-02"
    with pytest.raises(EvidenceError, match="digest mismatch"):
        Evidence.from_dict(record)
    with pytest.raises(EvidenceError, match="malformed"):
        Evidence.from_dict({"kind": "k"})


def test_status_ordering() -> None:
    assert Status.worst([Status.PASS, Status.STALE, Status.EXCEPTED]) is Status.STALE
    assert Status.worst([Status.FAIL, Status.NO_EVIDENCE]) is Status.FAIL
    assert Status.worst([]) is Status.NO_EVIDENCE
    assert Status.EXCEPTED.is_effective and not Status.STALE.is_effective
    assert [s.rank for s in Status] == sorted(s.rank for s in Status)
