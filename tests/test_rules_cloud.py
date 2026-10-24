"""Cloud configuration rules."""

from __future__ import annotations

from typing import Any

import pytest

from controlmap.errors import RuleError
from controlmap.model import Evidence

from .conftest import ev, resources, run_rule

ACCOUNT = "aws:1"


def iam(**over: Any) -> Evidence:
    data: dict[str, Any] = {
        "root_mfa_enabled": True,
        "root_access_keys_present": False,
        "password_policy": {"minimum_length": 16, "reuse_prevention": 24},
    }
    data.update(over)
    return ev("cloud.iam_account", data, subject=ACCOUNT)


def bucket(name: str, encrypted: bool = True, blocked: bool = True) -> dict[str, Any]:
    flags = dict.fromkeys(
        ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"),
        blocked,
    )
    return {
        "name": name,
        "encrypted": encrypted,
        "encryption_algorithms": ["AES256"] if encrypted else [],
        "public_access_block": flags,
        "all_public_access_blocked": blocked,
    }


def buckets(*items: dict[str, Any]) -> Evidence:
    return ev("cloud.storage_buckets", {"buckets": list(items)}, subject=ACCOUNT)


def test_root_account_protected() -> None:
    assert run_rule("cloud.root_account_protected", [iam()]).findings == []
    outcome = run_rule(
        "cloud.root_account_protected", [iam(root_mfa_enabled=False, root_access_keys_present=True)]
    )
    assert [f.message for f in outcome.findings] == ["root account has no MFA", "root account has access keys"]


def test_password_policy() -> None:
    assert run_rule("cloud.password_policy", [iam()], {"min_reuse_prevention": 12}).findings == []
    weak = iam(password_policy={"minimum_length": 8, "reuse_prevention": None})
    outcome = run_rule("cloud.password_policy", [weak], {"min_reuse_prevention": 12})
    assert "minimum length 8 < 14" in outcome.findings[0].message
    assert "remembers 0 passwords" in outcome.findings[0].message
    missing = run_rule("cloud.password_policy", [iam(password_policy=None)])
    assert missing.findings[0].message == "no account password policy is set"


def test_storage_encrypted() -> None:
    assert run_rule("cloud.storage_encrypted", [buckets(bucket("a"))]).findings == []
    outcome = run_rule("cloud.storage_encrypted", [buckets(bucket("a"), bucket("b", encrypted=False))])
    assert (outcome.checked, resources(outcome)) == (2, ["s3:b"])


def test_storage_public_access_blocked() -> None:
    assert run_rule("cloud.storage_public_access_blocked", [buckets(bucket("a"))]).findings == []
    partial = bucket("p")
    partial["public_access_block"]["restrict_public_buckets"] = False
    partial["all_public_access_blocked"] = False
    outcome = run_rule("cloud.storage_public_access_blocked", [buckets(partial, bucket("o", blocked=False))])
    assert resources(outcome) == ["s3:o", "s3:p"]
    assert outcome.findings[0].message.endswith("restrict_public_buckets")


def trail(name: str, **over: Any) -> dict[str, Any]:
    data = {"name": name, "multi_region": True, "is_logging": True, "log_file_validation": True}
    data.update(over)
    return data


def test_audit_logging() -> None:
    good = ev("cloud.audit_trails", {"trails": [trail("t1"), trail("t2", is_logging=False)]}, subject=ACCOUNT)
    assert run_rule("cloud.audit_logging", [good]).findings == []
    bad = ev(
        "cloud.audit_trails",
        {"trails": [trail("t1", multi_region=False), trail("t2", is_logging=False, log_file_validation=False)]},
        subject=ACCOUNT,
    )
    outcome = run_rule("cloud.audit_logging", [bad])
    assert resources(outcome) == ["aws:1:trail/t1", "aws:1:trail/t2"]
    assert outcome.findings[1].message == "logging is stopped; log-file validation disabled"
    empty = ev("cloud.audit_trails", {"trails": []}, subject=ACCOUNT)
    assert run_rule("cloud.audit_logging", [empty]).findings[0].message == "no audit trails configured"


def key(key_id: str, **over: Any) -> dict[str, Any]:
    data = {
        "key_id": key_id,
        "alias": None,
        "manager": "CUSTOMER",
        "state": "Enabled",
        "spec": "SYMMETRIC_DEFAULT",
        "rotation_enabled": True,
    }
    data.update(over)
    return data


def test_kms_rotation() -> None:
    keys = [
        key("k1"),
        key("k2", alias="alias/off", rotation_enabled=False),
        key("k3", rotation_enabled=None),
        key("k4", manager="AWS", rotation_enabled=False),
        key("k5", state="Disabled", rotation_enabled=False),
        key("k6", spec="RSA_2048", rotation_enabled=False),
    ]
    outcome = run_rule("cloud.kms_rotation", [ev("cloud.kms_keys", {"keys": keys}, subject=ACCOUNT)])
    assert outcome.checked == 3
    assert resources(outcome) == ["kms:alias/off", "kms:k3"]


def group(group_id: str, *rules: dict[str, Any]) -> dict[str, Any]:
    return {"id": group_id, "name": group_id, "vpc_id": "v", "ingress": list(rules)}


def ingress(proto: str, low: int | None, high: int | None, *cidrs: str) -> dict[str, Any]:
    return {"protocol": proto, "from_port": low, "to_port": high, "cidrs": list(cidrs)}


def groups(*items: dict[str, Any]) -> Evidence:
    return ev("cloud.security_groups", {"groups": list(items)}, subject=ACCOUNT)


def test_admin_ports_restricted_passes_for_https_and_private_ssh() -> None:
    evidence = groups(
        group("sg-web", ingress("tcp", 443, 443, "0.0.0.0/0", "::/0")),
        group("sg-ssh", ingress("tcp", 22, 22, "10.0.0.0/8")),
        group("sg-icmp", ingress("icmp", -1, -1, "0.0.0.0/0")),
    )
    outcome = run_rule("cloud.admin_ports_restricted", [evidence])
    assert (outcome.checked, outcome.findings) == (3, [])


def test_admin_ports_restricted_flags_ranges_all_traffic_and_ipv6() -> None:
    evidence = groups(
        group("sg-range", ingress("tcp", 0, 65535, "0.0.0.0/0")),
        group("sg-all", ingress("-1", None, None, "0.0.0.0/0")),
        group("sg-v6", ingress("6", 3389, 3389, "::/0")),
        group("sg-noports", ingress("tcp", None, None, "0.0.0.0/0")),
    )
    outcome = run_rule("cloud.admin_ports_restricted", [evidence])
    messages = {f.resource: f.message for f in outcome.findings}
    assert messages == {
        "sg:sg-range": "port 22, port 3389 open to the internet",
        "sg:sg-all": "all traffic, port 22, port 3389 open to the internet",
        "sg:sg-v6": "port 3389 open to the internet",
        "sg:sg-noports": "port 22, port 3389 open to the internet",
    }
    custom = run_rule("cloud.admin_ports_restricted", [evidence], {"ports": [5432]})
    assert set(resources(custom)) == {"sg:sg-range", "sg:sg-all", "sg:sg-noports"}


def test_admin_ports_restricted_rejects_invalid_cidr() -> None:
    with pytest.raises(RuleError, match="invalid CIDR"):
        run_rule("cloud.admin_ports_restricted", [groups(group("g", ingress("tcp", 22, 22, "not-a-cidr")))])


def test_database_hardening() -> None:
    db = {"id": "db1", "storage_encrypted": True, "publicly_accessible": False, "backup_retention_days": 7}
    assert run_rule("cloud.database_hardening", [ev("cloud.databases", {"instances": [db]})]).findings == []
    bad = dict(db, storage_encrypted=False, publicly_accessible=True, backup_retention_days=1)
    outcome = run_rule("cloud.database_hardening", [ev("cloud.databases", {"instances": [bad]})])
    assert outcome.findings[0].message == "storage not encrypted; publicly accessible; backup retention 1d < 7d"
