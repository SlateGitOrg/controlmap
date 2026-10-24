"""Evidence package: build, determinism, signing, archives and tamper detection."""

from __future__ import annotations

import base64
import io
import json
import shutil
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from controlmap.canonical import pretty_json, sha256_bytes
from controlmap.errors import PackageError
from controlmap.model import Evidence
from controlmap.package import (
    build_package,
    generate_keypair,
    load_private_key,
    load_public_key,
    signing,
    verify_package,
)
from controlmap.package.archive import extract_archive
from controlmap.project import Evaluation, collect, evaluate_project, load_config

GENERATED = datetime(2026, 10, 1, 12, tzinfo=UTC)


@pytest.fixture
def evaluation(acme: Path) -> Evaluation:
    config = load_config(acme / "controlmap.yaml")
    assert collect(config).ok
    return evaluate_project(config)


def build(evaluation: Evaluation, out: Path, **kwargs: object) -> object:
    return build_package(
        out,
        run=evaluation.run,
        library=evaluation.library,
        library_source=evaluation.config.library_path,
        records=evaluation.records,
        store=evaluation.config.store(),
        generated_at=GENERATED,
        **kwargs,  # type: ignore[arg-type]
    )


def test_package_contents_and_verification(evaluation: Evaluation, tmp_path: Path) -> None:
    out = tmp_path / "pkg"
    build(evaluation, out)
    names = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    assert {"README.md", "index.html", "results.json", "manifest.json", "MANIFEST.sha256"} <= names
    assert "controls/AC-01.md" in names and "controls/AC-01.html" in names
    assert "library/controls.yaml" in names
    assert any(
        n.startswith("attachments/") and n.endswith("access-review-2026-q3.csv") for n in names
    )
    # 21 records are stored; the superseded Q2 access review is not relied on by any rule.
    assert sum(n.startswith("evidence/") for n in names) == 20
    assert not any("access-review-2026-q2" in n for n in names)
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["summary"]["FAIL"] == 7
    assert "supports a SOC 2 examination; it is not one" in (out / "README.md").read_text()
    report = verify_package(out)
    assert report.ok, report.problems
    assert report.evidence_records == 20
    assert report.signed is False


def test_html_is_escaped(evaluation: Evaluation, tmp_path: Path) -> None:
    build(evaluation, tmp_path / "pkg")
    html = (tmp_path / "pkg" / "controls" / "NW-01.html").read_text()
    assert "<script" not in html
    assert "s3:acme-public-assets" in html


def test_builds_are_byte_for_byte_reproducible(evaluation: Evaluation, tmp_path: Path) -> None:
    # the archive's top-level directory is the package name, so keep the names equal
    first = build(evaluation, tmp_path / "1" / "pkg", archive=tmp_path / "a.tar.gz")
    second = build(evaluation, tmp_path / "2" / "pkg", archive=tmp_path / "b.tar.gz")
    assert first.manifest_sha256 == second.manifest_sha256  # type: ignore[attr-defined]
    assert (tmp_path / "a.tar.gz").read_bytes() == (tmp_path / "b.tar.gz").read_bytes()


def test_existing_output_is_protected(evaluation: Evaluation, tmp_path: Path) -> None:
    out = tmp_path / "pkg"
    build(evaluation, out)
    with pytest.raises(PackageError, match="already exists"):
        build(evaluation, out)
    build(evaluation, out, force=True)
    other = tmp_path / "not-a-package"
    other.mkdir()
    with pytest.raises(PackageError, match="not a controlmap package"):
        build(evaluation, other, force=True)


def test_signed_package_with_trusted_key(evaluation: Evaluation, tmp_path: Path) -> None:
    fingerprint = generate_keypair(tmp_path / "k.pem", tmp_path / "k.pub")
    other = generate_keypair(tmp_path / "o.pem", tmp_path / "o.pub")
    assert (tmp_path / "k.pem").stat().st_mode & 0o777 == 0o600
    out = tmp_path / "pkg"
    build(evaluation, out, signing_key=load_private_key(tmp_path / "k.pem"))
    report = verify_package(out, public_key=load_public_key(tmp_path / "k.pub"))
    assert report.ok and report.signature_valid and report.trusted_key_match
    assert report.fingerprint == fingerprint
    assert fingerprint in (out / "index.html").read_text()

    wrong = verify_package(out, public_key=load_public_key(tmp_path / "o.pub"))
    assert not wrong.ok and wrong.trusted_key_match is False
    assert other != fingerprint

    signature = json.loads((out / "signature.json").read_text())
    signature["signature"] = base64.b64encode(b"\0" * 64).decode()
    (out / "signature.json").write_text(json.dumps(signature))
    forged = verify_package(out)
    assert forged.signature_valid is False
    assert "does not verify" in forged.problems[0]


def test_unsigned_package_fails_when_signature_required(
    evaluation: Evaluation, tmp_path: Path
) -> None:
    build(evaluation, tmp_path / "pkg")
    assert verify_package(tmp_path / "pkg", require_signature=True).problems == [
        "package is not signed"
    ]


def test_key_file_errors(tmp_path: Path) -> None:
    generate_keypair(tmp_path / "k.pem", tmp_path / "k.pub")
    with pytest.raises(PackageError, match="refusing to overwrite"):
        generate_keypair(tmp_path / "k.pem", tmp_path / "new.pub")
    with pytest.raises(PackageError, match="cannot load private key"):
        load_private_key(tmp_path / "k.pub")
    with pytest.raises(PackageError, match="cannot load public key"):
        load_public_key(tmp_path / "missing.pub")


def edit_manifest_consistently(out: Path, name: str, data: bytes) -> None:
    """An attacker who rewrites a file *and* the manifest + checksum list."""
    (out / name).write_bytes(data)
    manifest = json.loads((out / "manifest.json").read_text())
    for entry in manifest["files"]:
        if entry["path"] == name:
            entry["sha256"], entry["size"] = sha256_bytes(data), len(data)
    manifest_bytes = pretty_json(manifest).encode()
    (out / "manifest.json").write_bytes(manifest_bytes)
    lines = [f"{e['sha256']}  {e['path']}" for e in manifest["files"]]
    lines.append(f"{sha256_bytes(manifest_bytes)}  manifest.json")
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


@pytest.fixture
def package(evaluation: Evaluation, tmp_path: Path) -> Path:
    out = tmp_path / "pkg"
    build(evaluation, out, signing_key=_key(tmp_path))
    return out


def _key(tmp_path: Path) -> object:
    generate_keypair(tmp_path / "sign.pem", tmp_path / "sign.pub")
    return load_private_key(tmp_path / "sign.pem")


def test_modified_file_is_detected(package: Path) -> None:
    page = package / "controls" / "AC-01.md"
    page.write_text(page.read_text().replace("FAIL", "PASS"))
    problems = verify_package(package).problems
    assert any("content modified: controls/AC-01.md" in p for p in problems)
    assert any("size mismatch" in p for p in problems) or len(problems) >= 1


def test_deleted_and_added_files_are_detected(package: Path) -> None:
    (package / "controls" / "AC-02.html").unlink()
    (package / "evidence" / "extra.json").write_text("{}")
    problems = verify_package(package).problems
    assert "missing file: controls/AC-02.html" in problems
    assert "unlisted file: evidence/extra.json" in problems


def test_rewriting_manifest_breaks_the_signature(package: Path) -> None:
    edit_manifest_consistently(package, "README.md", b"all controls pass\n")
    report = verify_package(package)
    assert report.signature_valid is False
    assert report.problems == ["signature: manifest signature does not verify"]


def test_unsigned_consistent_rewrite_of_evidence_is_still_caught(package: Path) -> None:
    (package / "signature.json").unlink()
    evidence = sorted((package / "evidence").glob("*.json"))[0]
    record = json.loads(evidence.read_text())
    record["data"]["tampered"] = True
    edit_manifest_consistently(package, f"evidence/{evidence.name}", pretty_json(record).encode())
    problems = verify_package(package).problems
    assert any("invalid evidence record" in p and "digest mismatch" in p for p in problems)


def test_results_must_reference_packaged_evidence(package: Path) -> None:
    (package / "signature.json").unlink()
    results = json.loads((package / "results.json").read_text())
    results["controls"][0]["rules"][0]["evidence"][0]["digest"] = "0" * 64
    results["counts"]["PASS"] += 1
    edit_manifest_consistently(package, "results.json", pretty_json(results).encode())
    problems = verify_package(package).problems
    assert any("evidence/" + "0" * 64 in p for p in problems)
    assert "manifest summary does not match results.json counts" in problems


def test_checksum_list_must_agree(package: Path) -> None:
    text = (package / "MANIFEST.sha256").read_text().splitlines()
    text[0] = "0" * 64 + text[0][64:]
    text.append("garbage")
    (package / "MANIFEST.sha256").write_text("\n".join(text) + "\n")
    problems = verify_package(package).problems
    assert any(p.startswith("MANIFEST.sha256 disagrees") for p in problems)
    assert any("is malformed" in p for p in problems)
    (package / "MANIFEST.sha256").unlink()
    assert "missing MANIFEST.sha256" in verify_package(package).problems


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        (b"{", "cannot read manifest.json"),
        (b'{"format": "other"}', "format is not"),
        (b'{"format": "controlmap-package/1", "files": {}}', "'files' is not a list"),
    ],
)
def test_broken_manifests(package: Path, manifest: bytes, message: str) -> None:
    (package / "manifest.json").write_bytes(manifest)
    assert message in verify_package(package).problems[0]


def test_unsafe_manifest_entries(package: Path) -> None:
    manifest = json.loads((package / "manifest.json").read_text())
    manifest["files"] += [
        {"path": "../escape", "sha256": "0" * 64, "size": 0},
        {"path": "signature.json", "sha256": "0" * 64, "size": 0},
        {"path": "README.md", "sha256": "0" * 64, "size": 0},
        {"nope": 1},
    ]
    (package / "manifest.json").write_text(json.dumps(manifest))
    problems = verify_package(package).problems
    assert "manifest.json: unsafe or reserved path '../escape'" in problems
    assert "manifest.json: unsafe or reserved path 'signature.json'" in problems
    assert "manifest.json: README.md is listed twice" in problems
    assert "manifest.json: files[" in " ".join(problems)


def test_symlinks_are_rejected(package: Path) -> None:
    (package / "link.md").symlink_to(package / "README.md")
    assert "symbolic link in package: link.md" in verify_package(package).problems


def test_archive_round_trip_and_tampering(
    package: Path, tmp_path: Path, evaluation: Evaluation
) -> None:
    archive = tmp_path / "pkg.tar.gz"
    build(evaluation, tmp_path / "pkg2", archive=archive)
    assert verify_package(archive).ok
    bad = tmp_path / "bad.tgz"
    bad.write_bytes(b"not a tarball")
    assert "cannot read archive" in verify_package(bad).problems[0]
    assert "neither a package directory" in verify_package(tmp_path / "nothing").problems[0]


def _tar(path: Path, members: list[tarfile.TarInfo]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for info in members:
            tar.addfile(info, io.BytesIO(b"x" * info.size) if info.isfile() else None)
    return path


def test_archive_extraction_refuses_unsafe_members(tmp_path: Path) -> None:
    traversal = tarfile.TarInfo("pkg/../../evil")
    traversal.size = 1
    link = tarfile.TarInfo("pkg/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    two_roots = [tarfile.TarInfo("a/x"), tarfile.TarInfo("b/y")]
    for info in two_roots:
        info.size = 1
    cases = [
        ([traversal], "unsafe path"),
        ([link], "not a regular file"),
        (two_roots, "exactly one top-level directory"),
    ]
    for index, (members, message) in enumerate(cases):
        archive = _tar(tmp_path / f"a{index}.tar.gz", members)
        with pytest.raises(PackageError, match=message):
            extract_archive(archive, tmp_path / f"out{index}")


def test_missing_evidence_or_attachments_abort_the_build(
    evaluation: Evaluation, tmp_path: Path
) -> None:
    with pytest.raises(PackageError, match="not in the store"):
        build_package(
            tmp_path / "pkg",
            run=evaluation.run,
            library=evaluation.library,
            library_source=evaluation.config.library_path,
            records=[],
            store=evaluation.config.store(),
        )
    shutil.rmtree(evaluation.config.store_path / "attachments")
    with pytest.raises(PackageError, match="missing"):
        build(evaluation, tmp_path / "pkg")
    assert not (tmp_path / "pkg").exists()
    assert not list(tmp_path.glob(".controlmap-pkg-*"))  # staging dir cleaned up


def _attachment_files(out: Path) -> list[Path]:
    return sorted((out / "attachments").iterdir())


def _set_listing(out: Path, files: dict[str, bytes | None]) -> None:
    """Add, replace (bytes) or drop (None) files and rewrite manifest + checksums to match."""
    manifest = json.loads((out / "manifest.json").read_text())
    entries = {e["path"]: e for e in manifest["files"]}
    for name, data in files.items():
        if data is None:
            (out / name).unlink()
            entries.pop(name)
        else:
            (out / name).parent.mkdir(parents=True, exist_ok=True)
            (out / name).write_bytes(data)
            entries[name] = {"path": name, "sha256": sha256_bytes(data), "size": len(data)}
    manifest["files"] = sorted(entries.values(), key=lambda e: e["path"])
    (out / "manifest.json").write_bytes(pretty_json(manifest).encode())
    edit_manifest_consistently(out, "results.json", (out / "results.json").read_bytes())


def test_tampered_store_attachment_aborts_the_build(evaluation: Evaluation, tmp_path: Path) -> None:
    """Bytes swapped in the store after collection must never be packaged as evidence."""
    stored = sorted((evaluation.config.store_path / "attachments").glob("*/*"))
    assert stored
    with stored[0].open("ab") as handle:
        handle.write(b"forged,row\n")
    with pytest.raises(PackageError, match="does not match its evidence record"):
        build(evaluation, tmp_path / "pkg", signing_key=_key(tmp_path))
    assert not (tmp_path / "pkg").exists()
    assert not list(tmp_path.glob(".controlmap-pkg-*"))


def test_attachment_must_match_the_digest_its_evidence_record_names(
    package: Path, tmp_path: Path
) -> None:
    """A forged attachment with a consistent, validly *signed* manifest is still rejected."""
    target = _attachment_files(package)[0]
    name = f"attachments/{target.name}"
    edit_manifest_consistently(package, name, target.read_bytes() + b"forged,row\n")
    key = load_private_key(tmp_path / "sign.pem")
    signature = signing.sign(key, (package / "manifest.json").read_bytes())
    (package / "signature.json").write_bytes(pretty_json(signature).encode())
    report = verify_package(package)
    assert report.signature_valid is True
    expected = target.name.split("-", 1)[0]
    assert report.problems == [
        f"evidence/{_record_naming(package, name)}.json: attachment {name} hashes to "
        f"{sha256_bytes((package / name).read_bytes())[:16]}..., but the evidence record says "
        f"{expected[:16]}..."
    ]


def _record_naming(package: Path, member: str) -> str:
    for path in (package / "evidence").glob("*.json"):
        record = json.loads(path.read_text())
        if any(f"attachments/{a['sha256']}-{a['name']}" == member for a in record["attachments"]):
            return path.stem
    raise AssertionError(member)


def test_missing_extra_and_unsafe_attachments_are_reported(package: Path) -> None:
    (package / "signature.json").unlink()
    gone = f"attachments/{_attachment_files(package)[0].name}"
    owner = _record_naming(package, gone)
    record = json.loads((package / "evidence" / f"{owner}.json").read_text())
    record.pop("digest")
    record["attachments"][0]["name"] = "../../outside.txt"
    unsafe = Evidence.from_dict(record)
    _set_listing(
        package,
        {
            gone: None,
            "attachments/" + "0" * 64 + "-smuggled.txt": b"not evidence\n",
            f"evidence/{unsafe.digest}.json": pretty_json(unsafe.to_dict()).encode(),
        },
    )
    problems = verify_package(package).problems
    assert f"evidence/{owner}.json: attachment {gone} is not in the package" in problems
    assert (
        "attachments/" + "0" * 64 + "-smuggled.txt: attachment not named by any evidence record"
    ) in problems
    assert any(
        p.startswith(f"evidence/{unsafe.digest}.json: unsafe attachment name") for p in problems
    )
