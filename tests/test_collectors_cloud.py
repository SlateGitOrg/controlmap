"""AWS snapshot collector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from controlmap.errors import CollectorError

from .conftest import ACME
from .helpers import make_collector, write

SNAPSHOT = ACME / "data" / "aws" / "prod-snapshot-2026-09-28.json"


def collect(tmp_path: Path, snapshot: dict[str, Any] | str) -> list[Any]:
    text = snapshot if isinstance(snapshot, str) else json.dumps(snapshot)
    write(tmp_path / "snap.json", text)
    collector = make_collector({"name": "aws", "type": "aws_snapshot", "path": "snap.json"}, tmp_path)
    return collector.collect()


def test_acme_snapshot_normalizes_every_section(tmp_path: Path) -> None:
    records = collect(tmp_path, SNAPSHOT.read_text())
    by_kind = {r.kind: r for r in records}
    assert sorted(by_kind) == [
        "cloud.audit_trails",
        "cloud.databases",
        "cloud.iam_account",
        "cloud.kms_keys",
        "cloud.security_groups",
        "cloud.storage_buckets",
    ]
    assert {r.subject for r in records} == {"aws:111122223333"}
    assert str(records[0].collected_at.date()) == "2026-09-28"
    iam = by_kind["cloud.iam_account"].data
    assert iam["root_mfa_enabled"] is True
    assert iam["password_policy"]["minimum_length"] == 16
    buckets = {b["name"]: b for b in by_kind["cloud.storage_buckets"].data["buckets"]}
    assert buckets["acme-prod-data"]["encryption_algorithms"] == ["aws:kms"]
    assert buckets["acme-public-assets"]["all_public_access_blocked"] is False
    trails = by_kind["cloud.audit_trails"].data["trails"]
    assert trails[0]["is_logging"] and trails[0]["kms_encrypted"]
    keys = by_kind["cloud.kms_keys"].data["keys"]
    assert [k["rotation_enabled"] for k in keys] == [True, None]
    groups = {g["id"]: g for g in by_kind["cloud.security_groups"].data["groups"]}
    assert groups["sg-0web"]["ingress"][0]["cidrs"] == ["0.0.0.0/0", "::/0"]
    db = by_kind["cloud.databases"].data["instances"][0]
    assert (db["backup_retention_days"], db["multi_az"]) == (14, True)


def test_absent_sections_produce_no_records(tmp_path: Path) -> None:
    snapshot = {
        "format": "controlmap-aws-snapshot/1",
        "account_id": "9",
        "iam": {"account_summary": {"SummaryMap": {}}},
    }
    [record] = collect(tmp_path, snapshot)
    assert record.kind == "cloud.iam_account"
    assert record.data == {
        "account_id": "9",
        "password_policy": None,
        "root_access_keys_present": False,
        "root_mfa_enabled": False,
    }


def test_bucket_without_encryption_or_public_access_block(tmp_path: Path) -> None:
    snapshot = {"format": "controlmap-aws-snapshot/1", "account_id": "9", "s3": {"buckets": [{"Name": "b"}]}}
    [record] = collect(tmp_path, snapshot)
    bucket = record.data["buckets"][0]
    assert bucket["encrypted"] is False
    assert bucket["all_public_access_blocked"] is False


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        ("{not json", "invalid JSON"),
        ({"format": "other"}, "format must be"),
        ({"format": "controlmap-aws-snapshot/1"}, "missing account_id"),
        ({"format": "controlmap-aws-snapshot/1", "account_id": "1"}, "no known sections"),
        (
            {"format": "controlmap-aws-snapshot/1", "account_id": "1", "captured_at": "noon"},
            "captured_at",
        ),
        (
            {"format": "controlmap-aws-snapshot/1", "account_id": "1", "s3": {"buckets": [{}]}},
            "missing Name",
        ),
        (
            {"format": "controlmap-aws-snapshot/1", "account_id": "1", "s3": {"buckets": "x"}},
            "expected a list",
        ),
        (
            {
                "format": "controlmap-aws-snapshot/1",
                "account_id": "1",
                "ec2": {"describe_security_groups": {"SecurityGroups": [{"GroupId": "g", "IpPermissions": [{"FromPort": "22"}]}]}},
            },
            "port must be an integer",
        ),
        (
            {
                "format": "controlmap-aws-snapshot/1",
                "account_id": "1",
                "rds": {"describe_db_instances": {"DBInstances": [{"BackupRetentionPeriod": "lots"}]}},
            },
            "section rds",
        ),
        (
            {"format": "controlmap-aws-snapshot/1", "account_id": "1", "cloudtrail": {"describe_trails": {"trailList": [{}]}}},
            "missing Name",
        ),
    ],
)
def test_malformed_snapshots(tmp_path: Path, snapshot: dict[str, Any] | str, message: str) -> None:
    with pytest.raises(CollectorError, match=message):
        collect(tmp_path, snapshot)


def test_collected_at_setting_overrides_captured_at(tmp_path: Path) -> None:
    write(tmp_path / "snap.json", SNAPSHOT.read_text())
    collector = make_collector(
        {"name": "aws", "type": "aws_snapshot", "path": "snap.json", "collected_at": "2026-01-02"},
        tmp_path,
    )
    assert {str(r.collected_at) for r in collector.collect()} == {"2026-01-02 00:00:00+00:00"}
