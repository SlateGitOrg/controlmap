"""Content-addressed evidence store.

Layout::

    <root>/objects/<aa>/<digest>.json    one canonical JSON record per evidence item
    <root>/attachments/<aa>/<sha256>     raw bytes of attached files
    <root>/runs/<digest>.json            one manifest per successful collector run

Records are immutable and named by their digest, so collecting the same observation twice is
idempotent and history accumulates naturally: an evaluation "as of" a past date selects the
newest record per (kind, subject) collected on or before that date.

A run manifest lists the (kind, subject) pairs one collector produced in one run. The engine
uses the latest run per source to retire subjects that a source no longer reports (a repository
dropped from the config, a deleted document descriptor), so their last record is not evaluated
forever.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_bytes, sha256_file
from .errors import EvidenceError
from .model import Attachment, Evidence
from .timeutil import isoformat, parse_datetime

RUN_FORMAT = "controlmap-run/1"

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PutResult:
    digest: str
    created: bool


@dataclass(frozen=True)
class CollectionRun:
    """What one collector reported in one successful run.

    ``recorded_at`` is the wall-clock time of the run and orders runs of a source;
    ``collected_through`` is the newest ``collected_at`` among its records (the run's own
    time when it produced none) and decides from which evaluation date the run applies.
    """

    source: str
    recorded_at: datetime
    collected_through: datetime
    members: frozenset[tuple[str, str]]

    @classmethod
    def from_records(
        cls, source: str, records: Iterable[Evidence], recorded_at: datetime
    ) -> CollectionRun:
        records = list(records)
        through = max((r.collected_at for r in records), default=recorded_at)
        return cls(source, recorded_at, through, frozenset((r.kind, r.subject) for r in records))

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": RUN_FORMAT,
            "source": self.source,
            "recorded_at": isoformat(self.recorded_at),
            "collected_through": isoformat(self.collected_through),
            "subjects": [{"kind": k, "subject": s} for k, s in sorted(self.members)],
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> CollectionRun:
        if doc.get("format") != RUN_FORMAT:
            raise EvidenceError(f"collection run is not {RUN_FORMAT!r}")
        try:
            return cls(
                source=str(doc["source"]),
                recorded_at=parse_datetime(doc["recorded_at"], field="recorded_at"),
                collected_through=parse_datetime(
                    doc["collected_through"], field="collected_through"
                ),
                members=frozenset((str(m["kind"]), str(m["subject"])) for m in doc["subjects"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(f"malformed collection run: {exc}") from exc

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))


class EvidenceStore:
    """A directory of immutable evidence records."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._objects = root / "objects"
        self._attachments = root / "attachments"
        self._runs = root / "runs"

    def _object_path(self, digest: str) -> Path:
        return self._objects / digest[:2] / f"{digest}.json"

    def attachment_path(self, sha256: str) -> Path:
        return self._attachments / sha256[:2] / sha256

    def put(self, evidence: Evidence) -> PutResult:
        """Store a record (and copies of its attachments). Re-putting is a no-op."""
        for attachment in evidence.attachments:
            self._put_attachment(attachment)
        digest = evidence.digest
        path = self._object_path(digest)
        if path.exists():
            return PutResult(digest, created=False)
        _atomic_write(path, canonical_json(evidence.to_dict()))
        log.debug("stored %s %s -> %s", evidence.kind, evidence.subject, digest[:12])
        return PutResult(digest, created=True)

    def put_many(self, items: Iterable[Evidence]) -> list[PutResult]:
        return [self.put(item) for item in items]

    def _put_attachment(self, attachment: Attachment) -> None:
        target = self.attachment_path(attachment.sha256)
        if target.exists():
            return
        source = Path(attachment.source_path)
        if not source.is_file():
            raise EvidenceError(f"attachment {attachment.name}: {source} is not a file")
        digest, _ = sha256_file(source)
        if digest != attachment.sha256:
            raise EvidenceError(
                f"attachment {attachment.name} changed since collection "
                f"(expected {attachment.sha256}, found {digest})"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        shutil.copyfile(source, tmp)
        tmp.replace(target)

    def get(self, digest: str) -> Evidence:
        path = self._object_path(digest)
        if not path.is_file():
            raise EvidenceError(f"no evidence with digest {digest}")
        return self._load(path)

    def _load(self, path: Path) -> Evidence:
        try:
            record = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"cannot read evidence record {path}: {exc}") from exc
        evidence = Evidence.from_dict(record)
        if path.stem != evidence.digest:
            raise EvidenceError(f"evidence record {path.name} does not match its content digest")
        return evidence

    def __iter__(self) -> Iterator[Evidence]:
        if not self._objects.is_dir():
            return
        for path in sorted(self._objects.glob("*/*.json")):
            yield self._load(path)

    def put_run(self, run: CollectionRun) -> str:
        """Record a collector run manifest (idempotent: runs are named by their digest)."""
        digest = run.digest
        path = self._runs / f"{digest}.json"
        if not path.exists():
            _atomic_write(path, canonical_json(run.to_dict()))
        return digest

    def runs(self) -> list[CollectionRun]:
        """All recorded collector runs, re-hashed against their file names."""
        if not self._runs.is_dir():
            return []
        runs = []
        for path in sorted(self._runs.glob("*.json")):
            try:
                run = CollectionRun.from_dict(json.loads(path.read_bytes()))
            except (OSError, json.JSONDecodeError) as exc:
                raise EvidenceError(f"cannot read collection run {path}: {exc}") from exc
            if path.stem != run.digest:
                raise EvidenceError(f"collection run {path.name} does not match its content digest")
            runs.append(run)
        return runs

    def __len__(self) -> int:
        if not self._objects.is_dir():
            return 0
        return sum(1 for _ in self._objects.glob("*/*.json"))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        Path(tmp_name).replace(path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
