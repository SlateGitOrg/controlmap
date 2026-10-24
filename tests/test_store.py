"""Content-addressed evidence store."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from controlmap.canonical import sha256_file
from controlmap.errors import EvidenceError
from controlmap.model import Attachment, Evidence
from controlmap.store import EvidenceStore


def record(value: int, attachments: tuple[Attachment, ...] = ()) -> Evidence:
    return Evidence(
        "k", "s", "src", datetime(2026, 9, 30, tzinfo=UTC), {"v": value}, "o", attachments
    )


def test_put_is_idempotent_and_round_trips(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    assert len(store) == 0
    assert list(store) == []
    first = store.put(record(1))
    again = store.put(record(1))
    store.put_many([record(2), record(3)])
    assert first.created and not again.created
    assert len(store) == 3
    assert store.get(first.digest) == record(1)
    assert sorted(r.data["v"] for r in store) == [1, 2, 3]


def test_attachments_are_copied_and_verified(tmp_path: Path) -> None:
    source = tmp_path / "review.csv"
    source.write_text("a,b\n", encoding="utf-8")
    digest, size = sha256_file(source)
    store = EvidenceStore(tmp_path / "store")
    store.put(record(1, (Attachment("review.csv", digest, size, str(source)),)))
    assert store.attachment_path(digest).read_text(encoding="utf-8") == "a,b\n"

    source.write_text("changed\n", encoding="utf-8")
    with pytest.raises(EvidenceError, match="changed since collection"):
        store.put(record(2, (Attachment("review.csv", digest[::-1], size, str(source)),)))
    with pytest.raises(EvidenceError, match="is not a file"):
        store.put(record(3, (Attachment("x", "0" * 64, 1, str(tmp_path / "missing")),)))


def test_tampered_or_corrupt_records_are_detected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    digest = store.put(record(1)).digest
    path = tmp_path / "objects" / digest[:2] / f"{digest}.json"
    path.write_bytes(path.read_bytes().replace(b'"v":1', b'"v":9'))
    with pytest.raises(EvidenceError, match="digest mismatch"):
        store.get(digest)
    path.write_bytes(b"{")
    with pytest.raises(EvidenceError, match="cannot read"):
        list(store)
    with pytest.raises(EvidenceError, match="no evidence"):
        store.get("f" * 64)


def test_record_stored_under_wrong_name_is_rejected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    digest = store.put(record(1)).digest
    source = tmp_path / "objects" / digest[:2] / f"{digest}.json"
    wrong = tmp_path / "objects" / "ff" / f"{'f' * 64}.json"
    wrong.parent.mkdir(parents=True)
    wrong.write_bytes(source.read_bytes())
    with pytest.raises(EvidenceError, match="does not match its content digest"):
        store.get("f" * 64)
