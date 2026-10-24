"""Manual document collector and the collector registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest

from controlmap.collectors import Collector, collector_types, register_collector
from controlmap.errors import CollectorError, ConfigError
from controlmap.model import Evidence

from .conftest import ACME
from .helpers import make_collector, write, write_yaml


def collect_docs(tmp_path: Path) -> list[Evidence]:
    return make_collector(
        {"name": "docs", "type": "manual_documents", "path": "docs"}, tmp_path
    ).collect()


def doc(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "kind": "access_review",
        "title": "Q3 review",
        "performed_on": "2026-07-15",
    }
    data.update(over)
    return data


def test_acme_documents_are_collected_with_hashed_attachments(tmp_path: Path) -> None:
    collector = make_collector(
        {"name": "docs", "type": "manual_documents", "path": str(ACME / "data" / "documents")},
        tmp_path,
    )
    records = {r.subject: r for r in collector.collect()}
    assert sorted(records) == [
        "access-review-2026-q2",
        "access-review-2026-q3",
        "infosec-policy-review-2026",
        "ir-tabletop-2025",
        "risk-assessment-2026",
        "vuln-scan-review-2026-09",
    ]
    q3 = records["access-review-2026-q3"]
    assert q3.kind == "manual.access_review"
    assert q3.data["performed_on"] == "2026-07-15"
    assert str(q3.collected_at) == "2026-07-18 15:30:00+00:00"
    [attachment] = q3.attachments
    assert attachment.name == "access-review-2026-q3.csv"
    assert len(attachment.sha256) == 64


def test_descriptor_id_overrides_subject_and_clock_is_fallback(tmp_path: Path) -> None:
    write_yaml(tmp_path / "docs" / "a.yml", doc(id="custom"))
    [record] = collect_docs(tmp_path)
    assert record.subject == "custom"
    assert str(record.collected_at) == "2026-09-30 12:00:00+00:00"


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        (doc(kind="Access Review"), "kind must match"),
        (doc(approved_on="2026-07-01"), "approved_on is before performed_on"),
        (doc(attachments=["../escape.txt"]), "escapes the documents directory"),
        (doc(attachments=["missing.pdf"]), "not found"),
        (doc(colour="red"), "unknown key"),
        ({"kind": "x", "performed_on": "2026-01-01"}, "missing required key 'title'"),
    ],
)
def test_bad_descriptors(tmp_path: Path, descriptor: dict[str, Any], message: str) -> None:
    write(tmp_path / "escape.txt", "x")
    write_yaml(tmp_path / "docs" / "d.yaml", descriptor)
    with pytest.raises(CollectorError, match=message):
        collect_docs(tmp_path)


def test_invalid_yaml_and_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(CollectorError, match="not a directory"):
        collect_docs(tmp_path)
    write(tmp_path / "docs" / "d.yaml", "kind: [unclosed\n")
    with pytest.raises(CollectorError, match="invalid YAML"):
        collect_docs(tmp_path)


def test_registry_lists_builtins_and_rejects_unknown_types(tmp_path: Path) -> None:
    assert {name for name in collector_types() if not name.startswith("test_")} == {
        "aws_snapshot",
        "endpoint_csv",
        "github",
        "hris_csv",
        "idp_csv",
        "manual_documents",
    }
    with pytest.raises(ConfigError, match="unknown collector type 'ldap'"):
        make_collector({"name": "x", "type": "ldap"}, tmp_path)
    with pytest.raises(ConfigError, match="unknown key"):
        make_collector({"name": "x", "type": "hris_csv", "path": "p", "extra": 1}, tmp_path)


def test_custom_collector_registration(tmp_path: Path) -> None:
    @register_collector
    class StaticCollector(Collector):
        type_name: ClassVar[str] = "test_static"
        allowed_keys: ClassVar[frozenset[str]] = frozenset({"value"})

        def collect(self) -> list[Evidence]:
            return [
                self.evidence(
                    "test.static",
                    "s",
                    {"v": self.settings.text("value")},
                    "inline",
                    self.collected_at(),
                )
            ]

    [record] = make_collector(
        {"name": "s", "type": "test_static", "value": "x"}, tmp_path
    ).collect()
    assert record.data == {"v": "x"}
    assert register_collector(StaticCollector) is StaticCollector  # idempotent

    class Clash(StaticCollector):
        pass

    with pytest.raises(ValueError, match="already registered"):
        register_collector(Clash)

    class Nameless(Collector):
        def collect(self) -> list[Evidence]:
            return []

    with pytest.raises(TypeError, match="must define type_name"):
        register_collector(Nameless)
