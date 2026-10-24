"""Content-addressed evidence store.

Layout::

    <root>/objects/<aa>/<digest>.json    one canonical JSON record per evidence item
    <root>/attachments/<aa>/<sha256>     raw bytes of attached files

Records are immutable and named by their digest, so collecting the same observation twice is
idempotent and history accumulates naturally: an evaluation "as of" a past date selects the
newest record per (kind, subject) collected on or before that date.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_json, sha256_file
from .errors import EvidenceError
from .model import Attachment, Evidence

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PutResult:
    digest: str
    created: bool


class EvidenceStore:
    """A directory of immutable evidence records."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._objects = root / "objects"
        self._attachments = root / "attachments"

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
