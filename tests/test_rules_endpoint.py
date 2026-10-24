"""Endpoint inventory rules."""

from __future__ import annotations

from typing import Any

import pytest

from controlmap.errors import RuleError
from controlmap.model import Evidence

from .conftest import ev, resources, run_rule
from .test_rules_identity import employee, roster


def device(device_id: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "device_id": device_id,
        "hostname": None,
        "serial": None,
        "owner_email": f"{device_id.lower()}@x.io",
        "platform": "macOS",
        "os_version": "15.0",
        "disk_encrypted": True,
        "edr_agent": "edr",
        "edr_last_seen": "2026-09-30",
        "screen_lock_minutes": 5,
        "last_checkin": "2026-09-30",
    }
    base.update(over)
    return base


def inventory(*items: dict[str, Any]) -> Evidence:
    return ev("endpoint.inventory", {"devices": list(items)}, subject="mdm:m")


def test_disk_encryption() -> None:
    assert run_rule("endpoint.disk_encryption", [inventory(device("D1"))]).findings == []
    outcome = run_rule(
        "endpoint.disk_encryption", [inventory(device("D1"), device("D2", disk_encrypted=False))]
    )
    assert (outcome.checked, resources(outcome)) == (2, ["device:D2"])


def test_edr_coverage() -> None:
    assert run_rule("endpoint.edr_coverage", [inventory(device("D1"))]).findings == []
    outcome = run_rule(
        "endpoint.edr_coverage",
        [
            inventory(
                device("D1", edr_agent=None),
                device("D2", edr_last_seen=None),
                device("D3", edr_last_seen="2026-09-01"),
                device("D4", edr_last_seen="2026-09-24"),
            )
        ],
    )
    assert resources(outcome) == ["device:D1", "device:D2", "device:D3"]
    messages = [f.message for f in outcome.findings]
    assert messages == [
        "no EDR agent installed",
        "EDR agent has never reported",
        "EDR agent silent for 30 days",
    ]


def test_os_supported() -> None:
    ok = inventory(device("D1"), device("D2", platform="Windows", os_version="10.0.22631.4169"))
    assert run_rule("endpoint.os_supported", [ok]).findings == []
    outcome = run_rule(
        "endpoint.os_supported",
        [
            inventory(
                device("D1", os_version="13.6.9"),
                device("D2", platform="Linux", os_version="20.04"),
            )
        ],
        {"minimum_versions": {"macOS": "14.0", "Linux": "22.04"}},
    )
    assert resources(outcome) == ["device:D1", "device:D2"]


def test_os_supported_flags_platforms_without_baseline_and_bad_versions() -> None:
    outcome = run_rule(
        "endpoint.os_supported",
        [inventory(device("D1", platform="Linux"))],
        {"minimum_versions": {"macOS": "14"}},
    )
    assert "no supported baseline" in outcome.findings[0].message
    with pytest.raises(RuleError, match="no numeric version"):
        run_rule("endpoint.os_supported", [inventory(device("D1", os_version="unknown"))])


def test_screen_lock() -> None:
    assert (
        run_rule("endpoint.screen_lock", [inventory(device("D1", screen_lock_minutes=15))]).findings
        == []
    )
    outcome = run_rule(
        "endpoint.screen_lock",
        [
            inventory(
                device("D1", screen_lock_minutes=None),
                device("D2", screen_lock_minutes=0),
                device("D3", screen_lock_minutes=30),
            )
        ],
    )
    assert resources(outcome) == ["device:D1", "device:D2", "device:D3"]
    assert "30 min" in outcome.findings[2].message


def test_inventory_reconciled_passes_when_everything_matches() -> None:
    outcome = run_rule(
        "endpoint.inventory_reconciled",
        [inventory(device("D1", owner_email="a@x.io")), roster(employee("a@x.io"))],
    )
    assert outcome.checked == 2
    assert outcome.findings == []


def test_inventory_reconciled_flags_every_mismatch() -> None:
    outcome = run_rule(
        "endpoint.inventory_reconciled",
        [
            inventory(
                device("D1", owner_email="left@x.io"),
                device("D2", owner_email="stranger@x.io"),
                device("D3", owner_email=None),
                device("D4", owner_email="a@x.io", last_checkin="2026-07-01"),
            ),
            roster(
                employee("a@x.io"),
                employee("nodevice@x.io"),
                employee("left@x.io", status="terminated", termination_date="2026-09-01"),
            ),
        ],
    )
    assert resources(outcome) == [
        "device:D1",
        "device:D2",
        "device:D3",
        "device:D4",
        "nodevice@x.io",
    ]
    relaxed = run_rule(
        "endpoint.inventory_reconciled",
        [
            inventory(device("D1", owner_email="a@x.io")),
            roster(employee("a@x.io"), employee("b@x.io")),
        ],
        {"require_device_per_employee": False},
    )
    assert relaxed.findings == []
    assert relaxed.checked == 1
