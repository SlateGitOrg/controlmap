"""Independent verification of an evidence package (directory or tar.gz archive).

Verification needs nothing but the package itself (plus, optionally, a trusted public key).
It checks, in order:

1. ``manifest.json`` parses, has the expected format and lists only safe relative paths;
2. every listed file exists with the recorded size and SHA-256;
3. no unlisted file is present (an attacker cannot smuggle in extra "evidence");
4. ``MANIFEST.sha256`` agrees with the manifest (so ``shasum -c`` is an equivalent check);
5. every ``evidence/<digest>.json`` record re-hashes to its own name;
6. every evidence digest referenced from ``results.json`` is present, and the manifest's
   status summary matches the results;
7. ``signature.json``, when present, verifies over ``manifest.json``; when a trusted public
   key is supplied, the signing key must be that key.

All problems are collected rather than stopping at the first, so one run tells an auditor
everything that is wrong with a package.
"""

from __future__ import annotations

import json
import logging
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..canonical import sha256_bytes, sha256_file
from ..errors import EvidenceError, PackageError
from ..model import Evidence
from . import signing
from .archive import extract_archive
from .builder import CHECKSUMS, FORMAT, INTEGRITY_FILES, MANIFEST, SIGNATURE

log = logging.getLogger(__name__)


@dataclass
class VerifyReport:
    """Outcome of verifying one package. ``ok`` is the only field a caller must check."""

    path: Path
    manifest_sha256: str = ""
    files_checked: int = 0
    evidence_records: int = 0
    signed: bool = False
    signature_valid: bool | None = None
    fingerprint: str | None = None
    trusted_key_match: bool | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "ok": self.ok,
            "manifest_sha256": self.manifest_sha256,
            "files_checked": self.files_checked,
            "evidence_records": self.evidence_records,
            "signed": self.signed,
            "signature_valid": self.signature_valid,
            "fingerprint": self.fingerprint,
            "trusted_key_match": self.trusted_key_match,
            "problems": list(self.problems),
        }


def is_archive(path: Path) -> bool:
    return path.is_file() and path.name.endswith((".tar.gz", ".tgz"))


def verify_package(
    path: Path,
    *,
    public_key: Ed25519PublicKey | None = None,
    require_signature: bool = False,
) -> VerifyReport:
    """Verify a package directory or archive. Never raises for integrity problems; they are
    reported in :attr:`VerifyReport.problems`."""
    if is_archive(path):
        with tempfile.TemporaryDirectory(prefix="controlmap-verify-") as tmp:
            try:
                root = extract_archive(path, Path(tmp))
            except PackageError as exc:
                return VerifyReport(path, problems=[str(exc)])
            report = _verify_directory(root, public_key, require_signature)
            report.path = path
            return report
    if not path.is_dir():
        return VerifyReport(path, problems=[f"{path} is neither a package directory nor archive"])
    return _verify_directory(path, public_key, require_signature)


def _safe_relative(name: str) -> bool:
    pure = PurePosixPath(name)
    return (
        bool(name)
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "\\" not in name
        and name not in INTEGRITY_FILES
    )


def _verify_directory(
    root: Path, public_key: Ed25519PublicKey | None, require_signature: bool
) -> VerifyReport:
    report = VerifyReport(root)
    manifest_path = root / MANIFEST
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        report.problems.append(f"cannot read {MANIFEST}: {exc}")
        return report
    report.manifest_sha256 = sha256_bytes(manifest_bytes)
    if not isinstance(manifest, Mapping) or manifest.get("format") != FORMAT:
        report.problems.append(f"{MANIFEST}: format is not {FORMAT!r}")
        return report
    entries = manifest.get("files")
    if not isinstance(entries, list):
        report.problems.append(f"{MANIFEST}: 'files' is not a list")
        return report

    listed = _check_files(root, entries, report)
    _check_unlisted(root, listed, report)
    _check_checksums(root, listed, report)
    _check_evidence(root, listed, report)
    _check_results(root, manifest, listed, report)
    _check_signature(root, manifest_bytes, public_key, require_signature, report)
    log.info("verified %s: %s", root, "OK" if report.ok else f"{len(report.problems)} problem(s)")
    return report


def _check_files(root: Path, entries: list[Any], report: VerifyReport) -> dict[str, str]:
    listed: dict[str, str] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or not {"path", "sha256", "size"} <= set(entry):
            report.problems.append(f"{MANIFEST}: files[{index}] is malformed")
            continue
        name = str(entry["path"])
        if not _safe_relative(name):
            report.problems.append(f"{MANIFEST}: unsafe or reserved path {name!r}")
            continue
        if name in listed:
            report.problems.append(f"{MANIFEST}: {name} is listed twice")
            continue
        listed[name] = str(entry["sha256"])
        target = root / name
        if not target.is_file() or target.is_symlink():
            report.problems.append(f"missing file: {name}")
            continue
        digest, size = sha256_file(target)
        report.files_checked += 1
        if size != entry["size"]:
            report.problems.append(
                f"size mismatch: {name} ({size} bytes, manifest {entry['size']})"
            )
        if digest != entry["sha256"]:
            report.problems.append(f"content modified: {name} (sha256 {digest[:16]}...)")
    return listed


def _check_unlisted(root: Path, listed: Mapping[str, str], report: VerifyReport) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            report.problems.append(f"symbolic link in package: {name}")
        elif name not in listed and name not in INTEGRITY_FILES:
            report.problems.append(f"unlisted file: {name}")


def _check_checksums(root: Path, listed: Mapping[str, str], report: VerifyReport) -> None:
    try:
        text = (root / CHECKSUMS).read_text(encoding="utf-8")
    except OSError:
        report.problems.append(f"missing {CHECKSUMS}")
        return
    recorded: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64:
            report.problems.append(f"{CHECKSUMS} line {number} is malformed")
            continue
        recorded[name] = digest
    expected = dict(listed)
    expected[MANIFEST] = report.manifest_sha256
    if recorded != expected:
        differing = sorted(
            name
            for name in set(recorded) | set(expected)
            if recorded.get(name) != expected.get(name)
        )
        report.problems.append(
            f"{CHECKSUMS} disagrees with {MANIFEST} for: {', '.join(differing[:5])}"
        )


def _check_evidence(root: Path, listed: Mapping[str, str], report: VerifyReport) -> None:
    for name in sorted(listed):
        if not (name.startswith("evidence/") and name.endswith(".json")):
            continue
        path = root / name
        if not path.is_file():
            continue  # already reported as missing
        report.evidence_records += 1
        try:
            record = Evidence.from_dict(json.loads(path.read_bytes()))
        except (json.JSONDecodeError, EvidenceError) as exc:
            report.problems.append(f"{name}: invalid evidence record: {exc}")
            continue
        if PurePosixPath(name).stem != record.digest:
            report.problems.append(f"{name}: record digest {record.digest[:16]}... differs")


def _check_results(
    root: Path, manifest: Mapping[str, Any], listed: Mapping[str, str], report: VerifyReport
) -> None:
    if "results.json" not in listed:
        report.problems.append("results.json is not listed in the manifest")
        return
    try:
        results = json.loads((root / "results.json").read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        report.problems.append(f"cannot read results.json: {exc}")
        return
    if manifest.get("summary") != results.get("counts"):
        report.problems.append("manifest summary does not match results.json counts")
    for control in results.get("controls", []):
        for rule in control.get("rules", []):
            for ref in rule.get("evidence", []):
                name = f"evidence/{ref.get('digest')}.json"
                if name not in listed:
                    report.problems.append(
                        f"{control.get('control_id')}/{rule.get('rule')} references {name}, "
                        "which is not in the package"
                    )


def _check_signature(
    root: Path,
    manifest_bytes: bytes,
    public_key: Ed25519PublicKey | None,
    require_signature: bool,
    report: VerifyReport,
) -> None:
    signature_path = root / SIGNATURE
    if not signature_path.is_file():
        if require_signature or public_key is not None:
            report.problems.append("package is not signed")
        return
    report.signed = True
    try:
        document = json.loads(signature_path.read_bytes())
        if not isinstance(document, dict):
            raise PackageError("signature.json is not an object")
        embedded = signing.verify_signature(document, manifest_bytes)
    except (OSError, json.JSONDecodeError, PackageError) as exc:
        report.signature_valid = False
        report.problems.append(f"signature: {exc}")
        return
    report.signature_valid = True
    report.fingerprint = signing.fingerprint(embedded)
    if public_key is not None:
        report.trusted_key_match = signing.fingerprint(public_key) == report.fingerprint
        if not report.trusted_key_match:
            report.problems.append(
                "package was signed by a different key than the trusted public key "
                f"(signer {report.fingerprint[:16]}...)"
            )
