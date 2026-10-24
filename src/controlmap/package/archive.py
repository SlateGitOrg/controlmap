"""Deterministic tar.gz archives of a package directory, and safe extraction."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

from ..errors import PackageError


def write_archive(directory: Path, target: Path) -> Path:
    """Archive ``directory`` with sorted members, zeroed mtimes/owners and fixed modes, so the
    archive digest depends only on file contents and names."""
    buffer = io.BytesIO()
    root = directory.name
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(p for p in directory.rglob("*") if p.is_file()):
            relative = path.relative_to(directory).as_posix()
            info = tarfile.TarInfo(f"{root}/{relative}")
            data = path.read_bytes()
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    target.parent.mkdir(parents=True, exist_ok=True)
    with (
        target.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz,
    ):
        gz.write(buffer.getvalue())
    return target


def extract_archive(archive: Path, destination: Path) -> Path:
    """Extract into ``destination`` refusing links, devices and path traversal.

    Returns the single top-level package directory.
    """
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            members = tar.getmembers()
            roots = set()
            for member in members:
                name = member.name
                if not (member.isfile() or member.isdir()):
                    raise PackageError(f"archive member {name!r} is not a regular file")
                parts = Path(name).parts
                if name.startswith("/") or ".." in parts or "\\" in name:
                    raise PackageError(f"archive member {name!r} has an unsafe path")
                roots.add(parts[0])
            if len(roots) != 1:
                raise PackageError("archive must contain exactly one top-level directory")
            tar.extractall(destination, members=members, filter="data")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise PackageError(f"cannot read archive {archive}: {exc}") from exc
    return destination / roots.pop()
