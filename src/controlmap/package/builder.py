"""Build the evidence package directory (and optionally a deterministic tar.gz).

Determinism: given the same evidence, library, register, ``as_of`` and ``generated_at``, the
package is byte-for-byte identical, so two parties can rebuild it and compare manifest digests.
``generated_at`` defaults to the current time but honours ``SOURCE_DATE_EPOCH``.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import __version__
from ..canonical import canonical_json, pretty_json, sha256_bytes
from ..crosswalk import build_crosswalk
from ..errors import PackageError
from ..library import Library
from ..model import EvaluationRun, Evidence
from ..render import DISCLAIMER, Renderer
from ..store import EvidenceStore
from ..timeutil import isoformat, utc_now
from . import signing
from .archive import write_archive

log = logging.getLogger(__name__)

FORMAT = "controlmap-package/1"
MANIFEST = "manifest.json"
CHECKSUMS = "MANIFEST.sha256"
SIGNATURE = "signature.json"
INTEGRITY_FILES = frozenset({MANIFEST, CHECKSUMS, SIGNATURE})


@dataclass(frozen=True)
class PackageInfo:
    path: Path
    files: int
    manifest_sha256: str
    signed: bool
    archive: Path | None


def _referenced_evidence(run: EvaluationRun, records: Mapping[str, Evidence]) -> list[Evidence]:
    digests = {ref.digest for c in run.controls for r in c.rules for ref in r.evidence}
    missing = sorted(digests - set(records))
    if missing:
        raise PackageError(f"results reference evidence not in the store: {', '.join(missing)}")
    return [records[d] for d in sorted(digests)]


def build_package(
    out_dir: Path,
    *,
    run: EvaluationRun,
    library: Library,
    library_source: Path,
    records: list[Evidence] | tuple[Evidence, ...],
    store: EvidenceStore,
    generated_at: datetime | None = None,
    signing_key: Ed25519PrivateKey | None = None,
    archive: Path | None = None,
    force: bool = False,
) -> PackageInfo:
    """Write the package to ``out_dir`` atomically (built in a sibling temp dir, then renamed)."""
    if out_dir.exists():
        if not force:
            raise PackageError(f"{out_dir} already exists (use --force to replace a package)")
        if not (out_dir / MANIFEST).is_file():
            raise PackageError(f"{out_dir} exists and is not a controlmap package; not replacing")
    generated = isoformat(generated_at or utc_now())
    by_digest = {r.digest: r for r in records}
    evidence = _referenced_evidence(run, by_digest)
    crosswalk = build_crosswalk(library, run)
    renderer = Renderer(library, run, crosswalk)
    fingerprint = signing.fingerprint(signing_key.public_key()) if signing_key else None

    files: dict[str, bytes] = {}
    for name, text in renderer.control_pages(generated).items():
        files[name] = text.encode("utf-8")
    overview = renderer.overview_pages(generated, __version__, signing_key is not None, fingerprint)
    for name, text in overview.items():
        files[name] = text.encode("utf-8")
    files["README.md"] = files.pop("summary.md")
    files["results.json"] = pretty_json(run.to_dict()).encode("utf-8")
    files["crosswalk.json"] = pretty_json(crosswalk.to_dict()).encode("utf-8")
    files["crosswalk.csv"] = crosswalk.to_csv().encode("utf-8")
    files["exceptions.json"] = pretty_json(run.exception_report).encode("utf-8")
    try:
        files[f"library/{library_source.name}"] = library_source.read_bytes()
    except OSError as exc:
        raise PackageError(f"cannot read library {library_source}: {exc}") from exc
    for record in evidence:
        files[f"evidence/{record.digest}.json"] = pretty_json(record.to_dict()).encode("utf-8")
    attachment_sources: dict[str, Path] = {}
    for record in evidence:
        for attachment in record.attachments:
            stored = store.attachment_path(attachment.sha256)
            if not stored.is_file():
                raise PackageError(f"attachment {attachment.name} ({attachment.sha256}) missing")
            attachment_sources[f"attachments/{attachment.sha256}-{attachment.name}"] = stored

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".controlmap-pkg-", dir=out_dir.parent))
    try:
        entries: list[dict[str, Any]] = []
        for name, data in sorted(files.items()):
            _write(staging / name, data)
            entries.append({"path": name, "sha256": sha256_bytes(data), "size": len(data)})
        for name, source in sorted(attachment_sources.items()):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            data = target.read_bytes()
            entries.append({"path": name, "sha256": sha256_bytes(data), "size": len(data)})
        entries.sort(key=lambda e: e["path"])
        manifest = {
            "format": FORMAT,
            "tool": {"name": "controlmap", "version": __version__},
            "company": run.company,
            "as_of": run.as_of.isoformat(),
            "generated_at": generated,
            "summary": run.counts(),
            "evidence_records": len(evidence),
            "files": entries,
        }
        manifest_bytes = pretty_json(manifest).encode("utf-8")
        _write(staging / MANIFEST, manifest_bytes)
        manifest_digest = sha256_bytes(manifest_bytes)
        lines = [f"{e['sha256']}  {e['path']}" for e in entries]
        lines.append(f"{manifest_digest}  {MANIFEST}")
        _write(
            staging / CHECKSUMS,
            ("\n".join(sorted(lines, key=lambda line: line[66:])) + "\n").encode(),
        )
        if signing_key is not None:
            signature = signing.sign(signing_key, manifest_bytes)
            _write(staging / SIGNATURE, pretty_json(signature).encode("utf-8"))
        if out_dir.exists():
            shutil.rmtree(out_dir)
        staging.rename(out_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    archive_path = write_archive(out_dir, archive) if archive else None
    total = len(entries) + 2 + (1 if signing_key else 0)
    log.info("package %s: %d files, manifest %s", out_dir, total, manifest_digest[:16])
    return PackageInfo(out_dir, total, manifest_digest, signing_key is not None, archive_path)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


__all__ = ["DISCLAIMER", "FORMAT", "PackageInfo", "build_package", "canonical_json"]
