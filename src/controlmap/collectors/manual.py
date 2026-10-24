"""Manually maintained evidence: policies, access-review sign-offs, incident-response tests.

Many SOC 2 controls are procedural. Their evidence is a document plus an approval, kept
in a directory of small YAML descriptors::

    kind: access_review          # becomes evidence kind "manual.access_review"
    title: Q3 2026 production access review
    performed_on: 2026-07-15     # when the activity happened (rules check its age)
    approved_by: VP Engineering  # a role, not a person's name
    approved_on: 2026-07-18
    summary: 41 accounts reviewed, 3 revoked.
    attachments: [q3-access-review.csv]   # hashed and copied into the package

Subject is the descriptor's ``id`` or, by default, its file stem.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from ..canonical import sha256_file
from ..errors import CollectorError, ControlmapError
from ..model import Attachment, Evidence
from ..settings import Settings, load_yaml
from .base import Collector, CollectorContext, register_collector

_KIND = re.compile(r"^[a-z][a-z0-9_]*$")
DOC_KEYS = frozenset(
    {
        "id",
        "kind",
        "title",
        "performed_on",
        "approved_by",
        "approved_on",
        "summary",
        "attachments",
        "recorded_at",
    }
)


@register_collector
class ManualDocumentsCollector(Collector):
    type_name: ClassVar[str] = "manual_documents"
    description: ClassVar[str] = "Directory of YAML descriptors for procedural evidence"
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"path"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        super().__init__(name, settings, context)
        self.path = settings.path("path")

    def collect(self) -> list[Evidence]:
        if not self.path.is_dir():
            raise CollectorError(f"{self.path}: not a directory")
        evidence = []
        files = sorted([*self.path.glob("*.yaml"), *self.path.glob("*.yml")])
        for file in files:
            try:
                evidence.append(self._read(file))
            except ControlmapError as exc:
                raise CollectorError(f"{file.name}: {exc}") from exc
        return evidence

    def _read(self, file: Path) -> Evidence:
        doc = Settings(load_yaml(file, CollectorError), file.name, CollectorError, file.parent)
        doc.reject_unknown(DOC_KEYS)
        kind = doc.text("kind")
        if not _KIND.match(kind):
            raise CollectorError(f"kind must match {_KIND.pattern}, got {kind!r}")
        performed = doc.day("performed_on")
        approved_on = doc.optional_day("approved_on")
        if approved_on is not None and approved_on < performed:
            raise CollectorError("approved_on is before performed_on")
        attachments = []
        for name in doc.text_list("attachments", []):
            path = (file.parent / name).resolve()
            if not path.is_relative_to(self.path.resolve()):
                raise CollectorError(f"attachment {name!r} escapes the documents directory")
            if not path.is_file():
                raise CollectorError(f"attachment {name!r} not found")
            digest, size = sha256_file(path)
            attachments.append(Attachment(Path(name).name, digest, size, str(path)))
        data = {
            "kind": kind,
            "title": doc.text("title"),
            "performed_on": performed,
            "approved_by": doc.optional_text("approved_by"),
            "approved_on": approved_on,
            "summary": doc.optional_text("summary"),
        }
        recorded = doc.optional_timestamp("recorded_at")
        return self.evidence(
            f"manual.{kind}",
            doc.text("id", file.stem),
            data,
            self.relpath(file),
            self.collected_at(recorded),
            attachments=tuple(attachments),
        )
