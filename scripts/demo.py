"""Offline end-to-end demo on the bundled synthetic company.

Copies examples/acme to a temporary directory, then runs the real CLI:
validate -> collect -> evaluate -> keygen -> package (signed + archive) -> verify,
tampers with one page to show detection, and finally collects GitHub evidence in API mode
from the bundled mock server on localhost. Nothing touches the network or the repository.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

from controlmap.cli import main
from controlmap.mockapi import BackgroundServer, MockGitHub

ROOT = Path(__file__).resolve().parent.parent
GENERATED_AT = "2026-10-01T12:00:00Z"


def step(title: str, *argv: str, cwd: Path, keep: str | None = None) -> int:
    """Run one CLI command in ``cwd`` and print its output (optionally only lines/blocks that
    mention ``keep``)."""
    print(f"\n$ controlmap {' '.join(argv)}", flush=True)
    out = io.StringIO()
    previous = Path.cwd()
    os.chdir(cwd)
    try:
        code = main(list(argv), out=out)
    finally:
        os.chdir(previous)
    text = out.getvalue()
    if keep is not None:
        blocks = text.split("\n\n")
        text = "\n\n".join(
            "\n".join(line for line in block.splitlines() if keep in line or block.startswith(keep))
            for block in blocks
            if keep in block
        )
        text += "\n(output filtered to " + keep + "* controls)\n"
    print(text.rstrip())
    print(f"[{title}: exit {code}]", flush=True)
    return code


def run(work: Path) -> int:
    shutil.copytree(
        ROOT / "examples" / "acme", work / "acme", ignore=shutil.ignore_patterns(".controlmap")
    )
    cfg = ("-c", "acme/controlmap.yaml")
    pkg, archive = "out/acme-2026-10-01", "out/acme-2026-10-01.tar.gz"
    failures = 0
    failures += step("validate", *cfg, "validate", cwd=work)
    failures += step("collect", *cfg, "collect", cwd=work)
    failures += step("evaluate", *cfg, "evaluate", "--details", cwd=work)
    failures += step(
        "keygen", "keygen", "--private", "out/signing.pem", "--public", "out/signing.pub", cwd=work
    )
    failures += step(
        "package",
        *cfg,
        "package",
        "--out",
        pkg,
        "--archive",
        archive,
        "--sign-key",
        "out/signing.pem",
        "--generated-at",
        GENERATED_AT,
        cwd=work,
    )
    failures += step("verify", "verify", archive, "--public-key", "out/signing.pub", cwd=work)

    print("\n# Tampering: flip AC-01 from FAIL to PASS in the auditor-facing page")
    page = work / pkg / "controls" / "AC-01.md"
    page.write_text(page.read_text(encoding="utf-8").replace("FAIL", "PASS"), encoding="utf-8")
    if step("verify tampered", "verify", pkg, cwd=work) == 0:
        print("ERROR: tampering was not detected", file=sys.stderr)
        failures += 1

    print("\n# API mode: GitHub evidence pulled from the offline mock REST API on localhost")
    mock = MockGitHub.from_file(work / "acme" / "data" / "mock-github.yaml")
    api = ("-c", "acme/controlmap.api.yaml")
    with BackgroundServer(mock) as server:
        os.environ["GITHUB_API_URL"] = server.base_url
        os.environ["GITHUB_TOKEN"] = "mock-token-not-a-secret"  # noqa: S105 - mock fixture value
        failures += step("collect (api)", *api, "collect", cwd=work)
        failures += step("evaluate (api)", *api, "evaluate", "--details", cwd=work, keep="CM-")
    return failures


def main_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="controlmap-demo-") as tmp:
        failures = run(Path(tmp))
    print("\ndemo finished:", "OK" if failures == 0 else f"{failures} step(s) failed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main_demo())
