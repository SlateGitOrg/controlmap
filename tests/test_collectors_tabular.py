"""CSV collectors: IdP users, HR roster and endpoint inventory."""

from __future__ import annotations

from pathlib import Path

import pytest

from controlmap.errors import CollectorError, ConfigError

from .helpers import FIXED, make_collector, write

IDP_HEADER = "id,email,status,mfa_factors,last_login,created,groups,type\n"


def idp(tmp_path: Path, rows: str, **extra: object) -> list[dict[str, object]]:
    write(tmp_path / "u.csv", IDP_HEADER + rows)
    collector = make_collector(
        {"name": "idp", "type": "idp_csv", "path": "u.csv", "tenant": "t", **extra}, tmp_path
    )
    [record] = collector.collect()
    assert record.kind == "idp.users"
    assert record.subject == "idp:t"
    users: list[dict[str, object]] = record.data["users"]
    return users


def test_idp_normalizes_status_factors_groups_and_admins(tmp_path: Path) -> None:
    users = idp(
        tmp_path,
        "1,Bob@X.io,LOCKED_OUT,okta_verify; webauthn,2026-09-01T10:00:00Z,2024-01-01,Eng|Admins,\n"
        "2,amy@x.io,Deactivated,None,,,,service\n"
        "\n"
        "3,cy@x.io,staged,,,,,human\n",
        admin_groups=["Admins"],
    )
    assert [u["email"] for u in users] == ["amy@x.io", "bob@x.io", "cy@x.io"]
    amy, bob, cy = users
    assert bob["status"] == "active"
    assert bob["mfa_factors"] == ["okta_verify", "webauthn"]
    assert bob["groups"] == ["Admins", "Eng"]
    assert bob["is_admin"] is True
    assert bob["last_login"] == "2026-09-01"
    assert amy["status"] == "deprovisioned"
    assert amy["mfa_enrolled"] is False
    assert amy["type"] == "service"
    assert cy["status"] == "pending"


def test_idp_okta_preset_and_column_overrides(tmp_path: Path) -> None:
    write(
        tmp_path / "okta.csv",
        "Okta ID,Login,Status,MFA Factors\n9,a@x.io,ACTIVE,Okta Verify\n",
    )
    collector = make_collector(
        {
            "name": "okta",
            "type": "idp_csv",
            "path": "okta.csv",
            "tenant": "t",
            "preset": "okta",
            "columns": {"email": "Login"},
        },
        tmp_path,
    )
    [record] = collector.collect()
    assert record.data["users"][0]["email"] == "a@x.io"
    assert record.collected_at == FIXED
    assert record.origin == "okta.csv"


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("1,a@x.io,weird,,,,,\n", "unknown account status"),
        ("1,not-an-email,active,,,,,\n", "not an e-mail address"),
        ("1,a@x.io,active,,,,,robot\n", "must be one of"),
        ("1,a@x.io,active,,someday,,,\n", "line 2, column last_login"),
        ("1,a@x.io,active,,,,,\n2,A@x.io,active,,,,,\n", "duplicate user a@x.io"),
    ],
)
def test_idp_rejects_bad_rows_with_line_numbers(tmp_path: Path, row: str, message: str) -> None:
    with pytest.raises(CollectorError, match=message):
        idp(tmp_path, row)


def test_csv_structure_errors(tmp_path: Path) -> None:
    write(tmp_path / "empty.csv", "")
    write(tmp_path / "missing.csv", "id,email\n1,a@x.io\n")
    for name, message in [("empty.csv", "empty CSV"), ("missing.csv", "missing required column")]:
        collector = make_collector(
            {"name": "i", "type": "idp_csv", "path": name, "tenant": "t"}, tmp_path
        )
        with pytest.raises(CollectorError, match=message):
            collector.collect()
    absent = make_collector({"name": "i", "type": "idp_csv", "path": "nope.csv", "tenant": "t"}, tmp_path)
    with pytest.raises(CollectorError, match="cannot read"):
        absent.collect()


def test_unknown_preset_and_column_are_config_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown preset"):
        make_collector({"name": "i", "type": "idp_csv", "path": "x", "tenant": "t", "preset": "ad"}, tmp_path)
    with pytest.raises(ConfigError, match="unknown key"):
        make_collector(
            {"name": "i", "type": "idp_csv", "path": "x", "tenant": "t", "columns": {"shoe": "x"}},
            tmp_path,
        )


HRIS_HEADER = "employee_id,email,status,start_date,termination_date,department,manager_email,training_completed_on\n"


def test_hris_roster(tmp_path: Path) -> None:
    write(
        tmp_path / "hr.csv",
        HRIS_HEADER
        + "E2,b@x.io,terminated,2020-01-01,2026-09-01,Eng,M@x.io,2026-01-01\n"
        + "E1,a@x.io,Active,2021-01-01,,,,\n",
    )
    [record] = make_collector({"name": "hr", "type": "hris_csv", "path": "hr.csv"}, tmp_path).collect()
    assert record.subject == "hris:hr"
    a, b = record.data["employees"]
    assert (a["email"], a["status"], a["department"], a["training_completed_on"]) == ("a@x.io", "active", None, None)
    assert (b["termination_date"], b["manager_email"]) == ("2026-09-01", "m@x.io")


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("E1,a@x.io,retired,2020-01-01,,,,\n", "must be one of"),
        ("E1,a@x.io,terminated,2020-01-01,,,,\n", "required for terminated"),
        ("E1,a@x.io,terminated,2020-01-01,2019-01-01,,,\n", "before start_date"),
        ("E1,a@x.io,active,2020-01-01,,,,\nE1,b@x.io,active,2020-01-01,,,,\n", "duplicate employee_id"),
    ],
)
def test_hris_rejects_bad_rows(tmp_path: Path, row: str, message: str) -> None:
    write(tmp_path / "hr.csv", HRIS_HEADER + row)
    collector = make_collector({"name": "hr", "type": "hris_csv", "path": "hr.csv"}, tmp_path)
    with pytest.raises(CollectorError, match=message):
        collector.collect()


DEVICE_HEADER = (
    "device_id,hostname,serial,owner_email,platform,os_version,disk_encrypted,edr_agent,"
    "edr_last_seen,screen_lock_minutes,last_checkin\n"
)


def test_endpoint_inventory(tmp_path: Path) -> None:
    write(
        tmp_path / "mdm.csv",
        DEVICE_HEADER
        + "D2,,,B@x.io,mac OS,14.6,Encrypted,,,,\n"
        + "D1,h1,s1,a@x.io,windows,10.0.22631,no,falcon,2026-09-29,10,2026-09-29\n",
    )
    [record] = make_collector({"name": "mdm", "type": "endpoint_csv", "path": "mdm.csv"}, tmp_path).collect()
    d1, d2 = record.data["devices"]
    assert (d1["platform"], d1["disk_encrypted"], d1["screen_lock_minutes"]) == ("Windows", False, 10)
    assert (d2["platform"], d2["disk_encrypted"], d2["owner_email"], d2["edr_agent"]) == ("macOS", True, "b@x.io", None)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("D1,,,a@x.io,beos,1,yes,,,,\n", "must be one of"),
        ("D1,,,a@x.io,macos,14,maybe,,,,\n", "not a boolean"),
        ("D1,,,a@x.io,macos,14,yes,,,ten,\n", "not an integer"),
        ("D1,,,a@x.io,macos,14,yes,,,-1,\n", "must not be negative"),
        ("D1,,,a@x.io,macos,14,yes,,,,\nD1,,,b@x.io,macos,14,yes,,,,\n", "duplicate device_id"),
    ],
)
def test_endpoint_rejects_bad_rows(tmp_path: Path, row: str, message: str) -> None:
    write(tmp_path / "mdm.csv", DEVICE_HEADER + row)
    collector = make_collector({"name": "mdm", "type": "endpoint_csv", "path": "mdm.csv"}, tmp_path)
    with pytest.raises(CollectorError, match=message):
        collector.collect()
