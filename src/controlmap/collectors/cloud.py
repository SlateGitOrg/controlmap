"""Cloud configuration snapshots (AWS-shaped).

The snapshot is one JSON document that bundles the raw output of read-only AWS CLI calls
(``aws iam get-account-summary``, ``aws s3api get-bucket-encryption``, ``aws cloudtrail
describe-trails`` ...). The collector never calls AWS itself: snapshots are produced by
whatever process the company already trusts (a scheduled job, an export from a CSPM) and
handed over as files. The exact format is documented in ``docs/COLLECTORS.md``.

Each top-level section becomes one evidence record with subject ``aws:<account_id>``. A
section that is absent from the snapshot produces **no** record (so dependent rules report
NO_EVIDENCE) rather than being treated as an empty, compliant list.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, ClassVar

from ..errors import CollectorError, ControlmapError
from ..model import Evidence
from ..settings import Settings
from ..timeutil import parse_datetime
from .base import Collector, CollectorContext, read_text, register_collector

SNAPSHOT_FORMAT = "controlmap-aws-snapshot/1"


def _obj(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CollectorError(f"{where}: expected an object, got {type(value).__name__}")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectorError(f"{where}: expected a list, got {type(value).__name__}")
    return value


def _port(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CollectorError(f"{where}: port must be an integer, got {value!r}")
    return value


def normalize_iam(section: Mapping[str, Any]) -> dict[str, Any]:
    summary = _obj(section.get("account_summary", {}), "iam.account_summary").get("SummaryMap", {})
    summary = _obj(summary, "iam.account_summary.SummaryMap")
    policy_doc = section.get("password_policy")
    policy: dict[str, Any] | None = None
    if policy_doc is not None:
        raw = _obj(_obj(policy_doc, "iam.password_policy").get("PasswordPolicy"), "PasswordPolicy")
        policy = {
            "minimum_length": int(raw.get("MinimumPasswordLength", 0)),
            "require_symbols": bool(raw.get("RequireSymbols", False)),
            "require_numbers": bool(raw.get("RequireNumbers", False)),
            "require_uppercase": bool(raw.get("RequireUppercaseCharacters", False)),
            "require_lowercase": bool(raw.get("RequireLowercaseCharacters", False)),
            "max_age_days": raw.get("MaxPasswordAge"),
            "reuse_prevention": raw.get("PasswordReusePrevention"),
        }
    return {
        "root_mfa_enabled": int(summary.get("AccountMFAEnabled", 0)) == 1,
        "root_access_keys_present": int(summary.get("AccountAccessKeysPresent", 0)) > 0,
        "password_policy": policy,
    }


def normalize_s3(section: Mapping[str, Any]) -> dict[str, Any]:
    buckets = []
    for i, raw in enumerate(_list(section.get("buckets"), "s3.buckets")):
        bucket = _obj(raw, f"s3.buckets[{i}]")
        name = str(bucket.get("Name") or "")
        if not name:
            raise CollectorError(f"s3.buckets[{i}]: missing Name")
        algorithms: list[str] = []
        encryption = bucket.get("encryption")
        if encryption is not None:
            config = _obj(encryption, f"s3 bucket {name} encryption").get(
                "ServerSideEncryptionConfiguration", {}
            )
            for rule in _list(
                _obj(config, "ServerSideEncryptionConfiguration").get("Rules"), "Rules"
            ):
                default = _obj(rule, "Rules[]").get("ApplyServerSideEncryptionByDefault") or {}
                algorithm = _obj(default, "ApplyServerSideEncryptionByDefault").get("SSEAlgorithm")
                if algorithm:
                    algorithms.append(str(algorithm))
        pab_doc = bucket.get("public_access_block")
        flags = {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        }
        if pab_doc is not None:
            pab = _obj(
                _obj(pab_doc, f"s3 bucket {name} public_access_block").get(
                    "PublicAccessBlockConfiguration", {}
                ),
                "PublicAccessBlockConfiguration",
            )
            flags = {
                "block_public_acls": bool(pab.get("BlockPublicAcls", False)),
                "ignore_public_acls": bool(pab.get("IgnorePublicAcls", False)),
                "block_public_policy": bool(pab.get("BlockPublicPolicy", False)),
                "restrict_public_buckets": bool(pab.get("RestrictPublicBuckets", False)),
            }
        buckets.append(
            {
                "name": name,
                "encrypted": bool(algorithms),
                "encryption_algorithms": sorted(set(algorithms)),
                "public_access_block": flags,
                "all_public_access_blocked": all(flags.values()),
            }
        )
    return {"buckets": sorted(buckets, key=lambda b: b["name"])}


def normalize_cloudtrail(section: Mapping[str, Any]) -> dict[str, Any]:
    described = _obj(section.get("describe_trails", {}), "cloudtrail.describe_trails")
    statuses = _obj(section.get("trail_status", {}), "cloudtrail.trail_status")
    trails = []
    for i, raw in enumerate(_list(described.get("trailList"), "trailList")):
        trail = _obj(raw, f"trailList[{i}]")
        name = str(trail.get("Name") or "")
        if not name:
            raise CollectorError(f"trailList[{i}]: missing Name")
        status = statuses.get(name) or statuses.get(str(trail.get("TrailARN", ""))) or {}
        trails.append(
            {
                "name": name,
                "home_region": trail.get("HomeRegion"),
                "multi_region": bool(trail.get("IsMultiRegionTrail", False)),
                "log_file_validation": bool(trail.get("LogFileValidationEnabled", False)),
                "is_logging": bool(_obj(status, f"trail_status[{name}]").get("IsLogging", False)),
                "kms_encrypted": bool(trail.get("KmsKeyId")),
            }
        )
    return {"trails": sorted(trails, key=lambda t: t["name"])}


def normalize_kms(section: Mapping[str, Any]) -> dict[str, Any]:
    keys = []
    for i, raw in enumerate(_list(section.get("keys"), "kms.keys")):
        entry = _obj(raw, f"kms.keys[{i}]")
        meta = _obj(entry.get("KeyMetadata"), f"kms.keys[{i}].KeyMetadata")
        rotation = entry.get("rotation")
        keys.append(
            {
                "key_id": str(meta.get("KeyId") or ""),
                "alias": entry.get("alias"),
                "manager": str(meta.get("KeyManager", "CUSTOMER")),
                "state": str(meta.get("KeyState", "Enabled")),
                "spec": str(meta.get("KeySpec", "SYMMETRIC_DEFAULT")),
                "rotation_enabled": bool(_obj(rotation, "rotation").get("KeyRotationEnabled"))
                if rotation is not None
                else None,
            }
        )
    return {"keys": sorted(keys, key=lambda k: k["key_id"])}


def normalize_security_groups(section: Mapping[str, Any]) -> dict[str, Any]:
    described = _obj(section.get("describe_security_groups", {}), "ec2.describe_security_groups")
    groups = []
    for i, raw in enumerate(_list(described.get("SecurityGroups"), "SecurityGroups")):
        group = _obj(raw, f"SecurityGroups[{i}]")
        group_id = str(group.get("GroupId") or "")
        ingress = []
        for j, perm_raw in enumerate(_list(group.get("IpPermissions"), "IpPermissions")):
            perm = _obj(perm_raw, f"{group_id}.IpPermissions[{j}]")
            cidrs = [
                str(_obj(r, "IpRanges[]").get("CidrIp"))
                for r in _list(perm.get("IpRanges"), "IpRanges")
            ]
            cidrs += [
                str(_obj(r, "Ipv6Ranges[]").get("CidrIpv6"))
                for r in _list(perm.get("Ipv6Ranges"), "Ipv6Ranges")
            ]
            ingress.append(
                {
                    "protocol": str(perm.get("IpProtocol", "-1")),
                    "from_port": _port(perm.get("FromPort"), f"{group_id} FromPort"),
                    "to_port": _port(perm.get("ToPort"), f"{group_id} ToPort"),
                    "cidrs": sorted(cidrs),
                }
            )
        groups.append(
            {
                "id": group_id,
                "name": str(group.get("GroupName", "")),
                "vpc_id": group.get("VpcId"),
                "ingress": ingress,
            }
        )
    return {"groups": sorted(groups, key=lambda g: g["id"])}


def normalize_rds(section: Mapping[str, Any]) -> dict[str, Any]:
    described = _obj(section.get("describe_db_instances", {}), "rds.describe_db_instances")
    instances = []
    for i, raw in enumerate(_list(described.get("DBInstances"), "DBInstances")):
        db = _obj(raw, f"DBInstances[{i}]")
        instances.append(
            {
                "id": str(db.get("DBInstanceIdentifier") or ""),
                "engine": str(db.get("Engine", "")),
                "storage_encrypted": bool(db.get("StorageEncrypted", False)),
                "publicly_accessible": bool(db.get("PubliclyAccessible", False)),
                "backup_retention_days": int(db.get("BackupRetentionPeriod", 0)),
                "multi_az": bool(db.get("MultiAZ", False)),
                "deletion_protection": bool(db.get("DeletionProtection", False)),
            }
        )
    return {"instances": sorted(instances, key=lambda d: d["id"])}


_SECTIONS: dict[str, tuple[str, Callable[[Mapping[str, Any]], dict[str, Any]]]] = {
    "iam": ("cloud.iam_account", normalize_iam),
    "s3": ("cloud.storage_buckets", normalize_s3),
    "cloudtrail": ("cloud.audit_trails", normalize_cloudtrail),
    "kms": ("cloud.kms_keys", normalize_kms),
    "ec2": ("cloud.security_groups", normalize_security_groups),
    "rds": ("cloud.databases", normalize_rds),
}


@register_collector
class AwsSnapshotCollector(Collector):
    type_name: ClassVar[str] = "aws_snapshot"
    description: ClassVar[str] = "AWS configuration snapshot (bundled read-only CLI outputs)"
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"path"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.path = settings.path("path")

    def collect(self) -> list[Evidence]:
        try:
            snapshot = json.loads(read_text(self.path))
        except json.JSONDecodeError as exc:
            raise CollectorError(f"{self.path}: invalid JSON: {exc}") from exc
        snapshot = _obj(snapshot, str(self.path))
        if snapshot.get("format") != SNAPSHOT_FORMAT:
            raise CollectorError(
                f"{self.path}: format must be {SNAPSHOT_FORMAT!r}, got {snapshot.get('format')!r}"
            )
        account = str(snapshot.get("account_id") or "")
        if not account:
            raise CollectorError(f"{self.path}: missing account_id")
        captured: Any = snapshot.get("captured_at")
        try:
            at = self.collected_at(parse_datetime(captured) if captured else None)
        except ControlmapError as exc:
            raise CollectorError(f"{self.path}: captured_at: {exc}") from exc
        origin = self.relpath(self.path)
        evidence = []
        for section, (kind, normalize) in _SECTIONS.items():
            if section not in snapshot:
                continue
            try:
                data = normalize(_obj(snapshot[section], section))
            except (TypeError, ValueError) as exc:
                raise CollectorError(f"{self.path}: section {section}: {exc}") from exc
            except CollectorError as exc:
                raise CollectorError(f"{self.path}: section {section}: {exc}") from exc
            data["account_id"] = account
            evidence.append(self.evidence(kind, f"aws:{account}", data, origin, at))
        if not evidence:
            raise CollectorError(f"{self.path}: snapshot contains no known sections")
        return evidence
