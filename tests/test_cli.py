"""The command-line interface, driven in-process."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from controlmap.cli import EXIT_CHECK_FAILED, EXIT_OK, EXIT_USAGE, main


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


@pytest.fixture
def config(acme: Path) -> str:
    path = str(acme / "controlmap.yaml")
    code, _ = run("-c", path, "collect")
    assert code == EXIT_OK
    return path


def test_validate(acme: Path) -> None:
    code, out = run("-c", str(acme / "controlmap.yaml"), "validate")
    assert code == EXIT_OK
    assert out == "config OK: 6 collectors, 22 controls, 27 rule bindings, 4 exceptions\n"


def test_collect_reports_each_collector(acme: Path) -> None:
    code, out = run(
        "-c", str(acme / "controlmap.yaml"), "collect", "--only", "okta", "--only", "jamf"
    )
    assert code == EXIT_OK
    assert "okta" in out and "jamf" in out and "aws-prod" not in out
    assert "2 new evidence record(s)" in out


def test_collect_failure_exit_codes(acme: Path) -> None:
    (acme / "data" / "idp" / "okta-users-2026-09-30.csv").write_text("broken\n", encoding="utf-8")
    code, out = run("-c", str(acme / "controlmap.yaml"), "collect")
    assert code == EXIT_CHECK_FAILED
    assert "ERROR: " in out and "missing required column" in out
    code, _ = run("-c", str(acme / "controlmap.yaml"), "collect", "--fail-fast")
    assert code == EXIT_USAGE
    code, _ = run("-c", str(acme / "controlmap.yaml"), "collect", "--only", "nope")
    assert code == EXIT_USAGE


def test_evaluate_table_details_and_fail_on(config: str) -> None:
    code, out = run("-c", config, "evaluate", "--details")
    assert code == EXIT_OK
    assert "AC-01    FAIL" in out
    assert "dev.k@acme.example: only disallowed MFA factors enrolled (SMS) [open]" in out
    assert "[excepted by EXC-2026-001]" in out
    assert "PASS 11 | EXCEPTED 2 | STALE 1 | NO_EVIDENCE 1 | FAIL 7" in out
    assert "supports an audit, not replaces it" in out
    code, _ = run("-c", config, "evaluate", "--fail-on", "FAIL,ERROR")
    assert code == EXIT_CHECK_FAILED
    code, _ = run("-c", config, "evaluate", "--fail-on", "ERROR")
    assert code == EXIT_OK


def test_evaluate_json_and_as_of(config: str) -> None:
    code, out = run("-c", config, "evaluate", "--json", "--as-of", "2026-09-01")
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["as_of"] == "2026-09-01"
    assert data["counts"]["NO_EVIDENCE"] > 1


def test_evaluate_with_empty_store_is_a_usage_error(
    acme: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run("-c", str(acme / "controlmap.yaml"), "evaluate")
    assert code == EXIT_USAGE
    assert "run 'controlmap collect' first" in capsys.readouterr().err


def test_bad_arguments_exit_with_usage(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["evaluate", "--as-of", "soon"], ["evaluate", "--fail-on", "MAYBE"], []):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 2
    code, _ = run("-c", "/nonexistent/controlmap.yaml", "validate")
    assert code == EXIT_USAGE
    assert "not found" in capsys.readouterr().err


def test_keygen_package_and_verify(config: str, tmp_path: Path) -> None:
    key, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    code, out = run("keygen", "--private", str(key), "--public", str(pub))
    assert code == EXIT_OK and "fingerprint" in out
    pkg, archive = tmp_path / "pkg", tmp_path / "pkg.tar.gz"
    code, out = run(
        "-c",
        config,
        "package",
        "--out",
        str(pkg),
        "--archive",
        str(archive),
        "--sign-key",
        str(key),
        "--generated-at",
        "2026-10-01T12:00:00Z",
    )
    assert code == EXIT_OK
    assert "signed: yes" in out and "archive:" in out
    code, out = run("verify", str(pkg), "--public-key", str(pub))
    assert code == EXIT_OK
    assert out.endswith("VERIFIED\n") and "signer matches the trusted public key" in out
    code, out = run("verify", str(archive), "--json")
    assert code == EXIT_OK and json.loads(out)["ok"] is True

    (pkg / "README.md").write_text("tampered", encoding="utf-8")
    code, out = run("verify", str(pkg))
    assert code == EXIT_CHECK_FAILED
    assert "FAIL: content modified: README.md" in out
    assert "NOT VERIFIED" in out

    code, out = run("-c", config, "package", "--out", str(tmp_path / "plain"))
    assert code == EXIT_OK and "signed: no" in out
    code, out = run("verify", str(tmp_path / "plain"))
    assert "integrity only, origin not proven" in out


def test_crosswalk_formats(acme: Path) -> None:
    config = str(acme / "controlmap.yaml")
    code, out = run("-c", config, "crosswalk")
    assert code == EXIT_OK
    assert "CC6.1" in out and "A.5.17" in out
    assert "in-scope criteria covered" in out
    _, csv_out = run("-c", config, "crosswalk", "--format", "csv")
    assert csv_out.startswith("tsc_criterion,tsc_label,control")
    _, json_out = run("-c", config, "crosswalk", "--format", "json")
    assert json.loads(json_out)["coverage"]["tsc_in_scope"] == 38


def test_exceptions_listing(acme: Path) -> None:
    config = str(acme / "controlmap.yaml")
    code, out = run("-c", config, "exceptions")
    assert code == EXIT_OK
    assert "EXC-2026-002" in out and "expiring-soon" in out
    assert "unused" not in out
    _, json_out = run("-c", config, "exceptions", "--json", "--as-of", "2027-01-01")
    states = {e["id"]: e["state"] for e in json.loads(json_out)["entries"]}
    assert states["EXC-2026-001"] == "expired"
    (acme / "exceptions.yaml").write_text("exceptions: []\n", encoding="utf-8")
    assert run("-c", config, "exceptions")[1] == "no exceptions registered\n"


def test_rules_and_collectors_listings() -> None:
    code, out = run("rules")
    assert code == EXIT_OK
    assert "idp.mfa_enforced" in out
    assert "doc_kind (str, required)" in out
    assert "evidence: (depends on params)" in out
    code, out = run("collectors")
    assert "aws_snapshot" in out and "manual_documents" in out


def test_module_entry_point() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "controlmap", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.startswith("controlmap ")
