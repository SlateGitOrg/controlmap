"""Rules over the endpoint (laptop/workstation) inventory."""

from __future__ import annotations

from typing import Any

from ..errors import RuleError
from ..model import Finding
from ..versions import compare_versions
from .base import Param, RuleContext, RuleOutcome, as_date, days_between, rule


def _devices(ctx: RuleContext) -> list[dict[str, Any]]:
    return [device for _, device in ctx.items("endpoint.inventory", "devices")]


def _label(device: dict[str, Any]) -> str:
    return f"device:{device['device_id']}"


@rule(
    "endpoint.disk_encryption",
    description="Every managed endpoint has full-disk encryption enabled.",
    requires=("endpoint.inventory",),
)
def disk_encryption(ctx: RuleContext) -> RuleOutcome:
    devices = _devices(ctx)
    findings = [
        Finding(_label(d), f"disk not encrypted ({d['platform']}, owner {d['owner_email']})")
        for d in devices
        if not d["disk_encrypted"]
    ]
    return RuleOutcome(len(devices), findings)


@rule(
    "endpoint.edr_coverage",
    description="Every endpoint runs the EDR/anti-malware agent and reported recently.",
    requires=("endpoint.inventory",),
    params=[Param("max_days_since_seen", "int", 7, "Maximum days since the agent last reported")],
)
def edr_coverage(ctx: RuleContext) -> RuleOutcome:
    devices = _devices(ctx)
    limit = ctx.param("max_days_since_seen")
    findings = []
    for device in devices:
        if not device["edr_agent"]:
            findings.append(Finding(_label(device), "no EDR agent installed"))
            continue
        seen = as_date(device["edr_last_seen"], f"{device['device_id']} edr_last_seen")
        if seen is None:
            findings.append(Finding(_label(device), "EDR agent has never reported"))
        elif days_between(seen, ctx.as_of) > limit:
            age = days_between(seen, ctx.as_of)
            findings.append(Finding(_label(device), f"EDR agent silent for {age} days"))
    return RuleOutcome(len(devices), findings)


@rule(
    "endpoint.os_supported",
    description="Endpoints run an operating system at or above the supported minimum.",
    requires=("endpoint.inventory",),
    params=[
        Param(
            "minimum_versions",
            "dict",
            {"macOS": "14.0", "Windows": "10.0.19045", "Linux": "0"},
            "Minimum OS version per platform",
        )
    ],
)
def os_supported(ctx: RuleContext) -> RuleOutcome:
    minimums: dict[str, Any] = ctx.param("minimum_versions")
    devices = _devices(ctx)
    findings = []
    for device in devices:
        minimum = minimums.get(device["platform"])
        if minimum is None:
            findings.append(
                Finding(_label(device), f"no supported baseline for {device['platform']}")
            )
            continue
        try:
            older = compare_versions(device["os_version"], str(minimum)) < 0
        except ValueError as exc:
            raise RuleError(f"{_label(device)}: {exc}") from exc
        if older:
            findings.append(
                Finding(
                    _label(device),
                    f"{device['platform']} {device['os_version']} is below minimum {minimum}",
                )
            )
    return RuleOutcome(len(devices), findings)


@rule(
    "endpoint.screen_lock",
    description="Endpoints lock the screen after a short period of inactivity.",
    requires=("endpoint.inventory",),
    params=[Param("max_minutes", "int", 15, "Maximum idle minutes before the screen locks")],
)
def screen_lock(ctx: RuleContext) -> RuleOutcome:
    devices = _devices(ctx)
    limit = ctx.param("max_minutes")
    findings = []
    for device in devices:
        minutes = device["screen_lock_minutes"]
        if minutes is None or minutes == 0:
            findings.append(Finding(_label(device), "screen lock not configured"))
        elif minutes > limit:
            findings.append(
                Finding(_label(device), f"screen locks after {minutes} min (limit {limit})")
            )
    return RuleOutcome(len(devices), findings)


@rule(
    "endpoint.inventory_reconciled",
    description="The device inventory reconciles with the HR roster: devices belong to current "
    "staff, active staff have a managed device, and devices keep checking in.",
    requires=("endpoint.inventory", "hris.roster"),
    params=[
        Param("require_device_per_employee", "bool", True, "Each active employee has a device"),
        Param("max_days_since_checkin", "int", 30, "Devices silent longer than this are lost"),
    ],
)
def inventory_reconciled(ctx: RuleContext) -> RuleOutcome:
    employees = {e["email"]: e for _, e in ctx.items("hris.roster", "employees")}
    devices = _devices(ctx)
    limit = ctx.param("max_days_since_checkin")
    findings = []
    owners: set[str] = set()
    for device in devices:
        owner = device["owner_email"]
        if owner:
            owners.add(owner)
        employee = employees.get(owner) if owner else None
        if employee is None:
            findings.append(
                Finding(_label(device), f"owner {owner or '(none)'} is not on the HR roster")
            )
        elif employee["status"] == "terminated":
            findings.append(Finding(_label(device), f"assigned to terminated employee {owner}"))
        checkin = as_date(device["last_checkin"], f"{device['device_id']} last_checkin")
        if checkin is None or days_between(checkin, ctx.as_of) > limit:
            findings.append(Finding(_label(device), "device has not checked in with MDM recently"))
    checked = len(devices)
    if ctx.param("require_device_per_employee"):
        active = [e for e in employees.values() if e["status"] == "active"]
        checked += len(active)
        findings.extend(
            Finding(e["email"], "active employee has no managed device")
            for e in active
            if e["email"] not in owners
        )
    return RuleOutcome(checked, findings)
