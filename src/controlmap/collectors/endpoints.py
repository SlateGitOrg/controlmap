"""Endpoint inventory exports (CSV) from an MDM/EDR console.

Evidence kind ``endpoint.inventory`` (subject ``mdm:<name>``).
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..errors import CollectorError
from ..model import Evidence
from ..settings import Settings
from .base import Collector, CollectorContext, register_collector
from .tabular import Row, column_map, read_rows, wrap_row_errors

FIELDS = (
    "device_id",
    "hostname",
    "serial",
    "owner_email",
    "platform",
    "os_version",
    "disk_encrypted",
    "edr_agent",
    "edr_last_seen",
    "screen_lock_minutes",
    "last_checkin",
)
REQUIRED = {"device_id", "owner_email", "platform", "os_version", "disk_encrypted"}
PRESETS = {"generic": {field: field for field in FIELDS}}
PLATFORMS = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}


def normalize_device(row: Row) -> dict[str, Any]:
    platform = PLATFORMS.get(row.get("platform").lower().replace(" ", ""))
    if platform is None:
        raise row.fail("platform", f"must be one of {sorted(PLATFORMS.values())}")
    lock = row.as_int("screen_lock_minutes")
    if lock is not None and lock < 0:
        raise row.fail("screen_lock_minutes", "must not be negative")
    return {
        "device_id": row.get("device_id"),
        "hostname": row.get("hostname") or None,
        "serial": row.get("serial") or None,
        "owner_email": row.get("owner_email").lower() or None,
        "platform": platform,
        "os_version": row.get("os_version"),
        "disk_encrypted": row.as_bool("disk_encrypted"),
        "edr_agent": row.get("edr_agent") or None,
        "edr_last_seen": row.as_date("edr_last_seen"),
        "screen_lock_minutes": lock,
        "last_checkin": row.as_date("last_checkin"),
    }


@register_collector
class EndpointCsvCollector(Collector):
    type_name: ClassVar[str] = "endpoint_csv"
    description: ClassVar[str] = "Endpoint inventory export (CSV)"
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"path", "preset", "columns"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.path = settings.path("path")
        self.columns = column_map(settings, PRESETS, "generic")

    def collect(self) -> list[Evidence]:
        devices = []
        seen: set[str] = set()
        for row in read_rows(self.path, self.columns, REQUIRED):
            try:
                device = normalize_device(row)
            except CollectorError as exc:
                raise wrap_row_errors(self.path, exc) from exc
            if device["device_id"] in seen:
                raise CollectorError(
                    f"{self.path}: line {row.line}: duplicate device_id {device['device_id']}"
                )
            seen.add(device["device_id"])
            devices.append(device)
        data = {"devices": sorted(devices, key=lambda d: d["device_id"])}
        return [
            self.evidence(
                "endpoint.inventory",
                f"mdm:{self.name}",
                data,
                self.relpath(self.path),
                self.collected_at(),
            )
        ]
