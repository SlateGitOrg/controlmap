"""Identity-provider user exports (CSV).

Evidence kind ``idp.users`` (subject ``idp:<tenant>``). Column names are configurable; the
``okta`` preset is modelled on an Okta-style admin user report and the ``generic`` preset uses
the normalized field names directly.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..errors import CollectorError
from ..model import Evidence
from ..settings import Settings
from .base import Collector, CollectorContext, register_collector
from .tabular import Row, column_map, read_rows, wrap_row_errors

FIELDS = ("id", "email", "status", "mfa_factors", "last_login", "created", "groups", "type")
REQUIRED = {"id", "email", "status", "mfa_factors"}

PRESETS: dict[str, dict[str, str]] = {
    "generic": {field: field for field in FIELDS},
    "okta": {
        "id": "Okta ID",
        "email": "Username",
        "status": "Status",
        "mfa_factors": "MFA Factors",
        "last_login": "Last Login",
        "created": "Created",
        "groups": "Groups",
        "type": "User Type",
    },
}

STATUS_MAP = {
    "active": "active",
    "password_expired": "active",
    "locked_out": "active",
    "recovery": "active",
    "provisioned": "pending",
    "staged": "pending",
    "pending": "pending",
    "suspended": "suspended",
    "deprovisioned": "deprovisioned",
    "deactivated": "deprovisioned",
    "disabled": "deprovisioned",
}
USER_TYPES = {"human", "service"}


def normalize_user(row: Row, admin_groups: set[str]) -> dict[str, Any]:
    raw_status = row.get("status").lower().replace(" ", "_")
    status = STATUS_MAP.get(raw_status)
    if status is None:
        raise row.fail("status", f"unknown account status {row.get('status')!r}")
    email = row.get("email").lower()
    if "@" not in email:
        raise row.fail("email", f"not an e-mail address: {row.get('email')!r}")
    user_type = (row.get("type") or "human").lower()
    if user_type not in USER_TYPES:
        raise row.fail("type", f"must be one of {sorted(USER_TYPES)}, got {user_type!r}")
    factors = [f for f in row.as_list("mfa_factors") if f.lower() not in ("none", "-")]
    groups = row.as_list("groups")
    return {
        "id": row.get("id"),
        "email": email,
        "status": status,
        "type": user_type,
        "mfa_factors": factors,
        "mfa_enrolled": bool(factors),
        "last_login": row.as_date("last_login"),
        "created": row.as_date("created"),
        "groups": groups,
        "is_admin": bool(admin_groups.intersection(groups)),
    }


@register_collector
class IdpCsvCollector(Collector):
    type_name: ClassVar[str] = "idp_csv"
    description: ClassVar[str] = "Identity-provider user export (CSV)"
    allowed_keys: ClassVar[frozenset[str]] = frozenset(
        {"path", "tenant", "preset", "columns", "admin_groups"}
    )

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.path = settings.path("path")
        self.tenant = settings.text("tenant")
        self.columns = column_map(settings, PRESETS, "generic")
        self.admin_groups = set(settings.text_list("admin_groups", []))

    def collect(self) -> list[Evidence]:
        users = []
        seen: set[str] = set()
        for row in read_rows(self.path, self.columns, REQUIRED):
            try:
                user = normalize_user(row, self.admin_groups)
            except CollectorError as exc:
                raise wrap_row_errors(self.path, exc) from exc
            if user["email"] in seen:
                raise CollectorError(
                    f"{self.path}: line {row.line}: duplicate user {user['email']}"
                )
            seen.add(user["email"])
            users.append(user)
        data = {
            "tenant": self.tenant,
            "admin_groups": sorted(self.admin_groups),
            "users": sorted(users, key=lambda u: u["email"]),
        }
        return [
            self.evidence(
                "idp.users",
                f"idp:{self.tenant}",
                data,
                self.relpath(self.path),
                self.collected_at(),
            )
        ]
