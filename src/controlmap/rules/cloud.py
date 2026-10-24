"""Rules over cloud configuration snapshots."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..errors import RuleError
from ..model import Finding
from .base import Param, RuleContext, RuleOutcome, rule

_OPEN_WORLD = ("0.0.0.0/0", "::/0")


@rule(
    "cloud.root_account_protected",
    description="The cloud root account has MFA and no long-lived access keys.",
    requires=("cloud.iam_account",),
)
def root_account_protected(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("cloud.iam_account")
    for record in records:
        if not record.data["root_mfa_enabled"]:
            findings.append(Finding(f"{record.subject}:root", "root account has no MFA"))
        if record.data["root_access_keys_present"]:
            findings.append(Finding(f"{record.subject}:root", "root account has access keys"))
    return RuleOutcome(len(records), findings)


@rule(
    "cloud.password_policy",
    description="Local cloud-console passwords meet the minimum length and reuse policy.",
    requires=("cloud.iam_account",),
    params=[
        Param("min_length", "int", 14, "Minimum password length"),
        Param("min_reuse_prevention", "int", 0, "Remembered previous passwords (0 = no check)"),
    ],
)
def password_policy(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("cloud.iam_account")
    for record in records:
        policy = record.data["password_policy"]
        if policy is None:
            findings.append(Finding(record.subject, "no account password policy is set"))
            continue
        problems = []
        if policy["minimum_length"] < ctx.param("min_length"):
            problems.append(
                f"minimum length {policy['minimum_length']} < {ctx.param('min_length')}"
            )
        required_reuse = ctx.param("min_reuse_prevention")
        if required_reuse and (policy["reuse_prevention"] or 0) < required_reuse:
            problems.append(
                f"remembers {policy['reuse_prevention'] or 0} passwords, needs {required_reuse}"
            )
        if problems:
            findings.append(Finding(record.subject, "; ".join(problems)))
    return RuleOutcome(len(records), findings)


@rule(
    "cloud.storage_encrypted",
    description="Every object-storage bucket has default server-side encryption.",
    requires=("cloud.storage_buckets",),
)
def storage_encrypted(ctx: RuleContext) -> RuleOutcome:
    buckets = ctx.items("cloud.storage_buckets", "buckets")
    findings = [
        Finding(f"s3:{bucket['name']}", "no default server-side encryption")
        for _, bucket in buckets
        if not bucket["encrypted"]
    ]
    return RuleOutcome(len(buckets), findings)


@rule(
    "cloud.storage_public_access_blocked",
    description="Every bucket blocks public ACLs and public bucket policies.",
    requires=("cloud.storage_buckets",),
)
def storage_public_access_blocked(ctx: RuleContext) -> RuleOutcome:
    buckets = ctx.items("cloud.storage_buckets", "buckets")
    findings = []
    for _, bucket in buckets:
        if bucket["all_public_access_blocked"]:
            continue
        missing = sorted(k for k, v in bucket["public_access_block"].items() if not v)
        findings.append(
            Finding(f"s3:{bucket['name']}", f"public access not blocked: {', '.join(missing)}")
        )
    return RuleOutcome(len(buckets), findings)


@rule(
    "cloud.audit_logging",
    description="At least one multi-region audit trail is logging with log-file validation.",
    requires=("cloud.audit_trails",),
)
def audit_logging(ctx: RuleContext) -> RuleOutcome:
    findings = []
    records = ctx.records("cloud.audit_trails")
    for record in records:
        trails = record.data["trails"]
        good = [
            t for t in trails if t["multi_region"] and t["is_logging"] and t["log_file_validation"]
        ]
        if good:
            continue
        if not trails:
            findings.append(Finding(record.subject, "no audit trails configured"))
            continue
        for trail in trails:
            problems = []
            if not trail["multi_region"]:
                problems.append("single-region")
            if not trail["is_logging"]:
                problems.append("logging is stopped")
            if not trail["log_file_validation"]:
                problems.append("log-file validation disabled")
            findings.append(Finding(f"{record.subject}:trail/{trail['name']}", "; ".join(problems)))
    return RuleOutcome(len(records), findings)


@rule(
    "cloud.kms_rotation",
    description="Enabled customer-managed symmetric keys rotate automatically.",
    requires=("cloud.kms_keys",),
)
def kms_rotation(ctx: RuleContext) -> RuleOutcome:
    keys = [
        key
        for _, key in ctx.items("cloud.kms_keys", "keys")
        if key["manager"] == "CUSTOMER"
        and key["state"] == "Enabled"
        and key["spec"] == "SYMMETRIC_DEFAULT"
    ]
    findings = []
    for key in keys:
        label = f"kms:{key['alias'] or key['key_id']}"
        if key["rotation_enabled"] is None:
            findings.append(Finding(label, "rotation status was not captured"))
        elif not key["rotation_enabled"]:
            findings.append(Finding(label, "automatic key rotation disabled"))
    return RuleOutcome(len(keys), findings)


def _covers_port(rule_: dict[str, Any], port: int) -> bool:
    if rule_["protocol"] == "-1":
        return True
    if rule_["protocol"] not in ("tcp", "6", "udp", "17"):
        return False
    low, high = rule_["from_port"], rule_["to_port"]
    if low is None or high is None:
        return True
    return int(low) <= port <= int(high)


def _is_world(cidr: str) -> bool:
    if cidr in _OPEN_WORLD:
        return True
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    except ValueError as exc:
        raise RuleError(f"invalid CIDR {cidr!r} in security group") from exc


@rule(
    "cloud.admin_ports_restricted",
    description="No security group exposes administrative ports (or all traffic) to the "
    "whole internet.",
    requires=("cloud.security_groups",),
    params=[Param("ports", "list", [22, 3389], "Administrative ports that must not be public")],
)
def admin_ports_restricted(ctx: RuleContext) -> RuleOutcome:
    ports = [int(p) for p in ctx.param("ports")]
    groups = ctx.items("cloud.security_groups", "groups")
    findings = []
    for _, group in groups:
        exposed: set[str] = set()
        for ingress in group["ingress"]:
            if not any(_is_world(c) for c in ingress["cidrs"]):
                continue
            if ingress["protocol"] == "-1":
                exposed.add("all traffic")
            exposed.update(f"port {p}" for p in ports if _covers_port(ingress, p))
        if exposed:
            findings.append(
                Finding(f"sg:{group['id']}", f"{', '.join(sorted(exposed))} open to the internet")
            )
    return RuleOutcome(len(groups), findings)


@rule(
    "cloud.database_hardening",
    description="Managed databases are encrypted, private, and keep automated backups.",
    requires=("cloud.databases",),
    params=[
        Param("min_backup_retention_days", "int", 7, "Minimum automated backup retention"),
    ],
)
def database_hardening(ctx: RuleContext) -> RuleOutcome:
    instances = ctx.items("cloud.databases", "instances")
    findings = []
    minimum = ctx.param("min_backup_retention_days")
    for _, db in instances:
        problems = []
        if not db["storage_encrypted"]:
            problems.append("storage not encrypted")
        if db["publicly_accessible"]:
            problems.append("publicly accessible")
        if db["backup_retention_days"] < minimum:
            problems.append(f"backup retention {db['backup_retention_days']}d < {minimum}d")
        if problems:
            findings.append(Finding(f"rds:{db['id']}", "; ".join(problems)))
    return RuleOutcome(len(instances), findings)
