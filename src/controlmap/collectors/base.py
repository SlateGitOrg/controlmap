"""Collector plugin interface and registry.

A collector turns one external source (an export file, a snapshot, an API) into normalized
:class:`~controlmap.model.Evidence` records. Built-in collectors register themselves with
:func:`register_collector`; third-party packages can add more through the
``controlmap.collectors`` entry-point group, with each entry point resolving to a
:class:`Collector` subclass.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, ClassVar

from ..errors import CollectorError, ConfigError
from ..model import Evidence
from ..settings import Settings
from ..timeutil import Clock, utc_now
from .http import Transport, UrllibTransport

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "controlmap.collectors"


@dataclass
class CollectorContext:
    """Services shared by all collectors in one run."""

    base_dir: Path
    clock: Clock = utc_now
    transport_factory: Callable[[], Transport] = UrllibTransport
    environ: Mapping[str, str] = field(default_factory=dict)


class Collector(ABC):
    """Base class for collectors.

    Subclasses set ``type_name`` and ``allowed_keys``, parse their settings in ``__init__``
    (so configuration errors surface before any collection starts) and implement
    :meth:`collect`.
    """

    type_name: ClassVar[str]
    description: ClassVar[str] = ""
    allowed_keys: ClassVar[frozenset[str]] = frozenset()
    _common_keys: ClassVar[frozenset[str]] = frozenset({"name", "type", "collected_at"})

    def __init__(self, name: str, settings: Settings, context: CollectorContext) -> None:
        settings.reject_unknown(self.allowed_keys | self._common_keys)
        self.name = name
        self.settings = settings
        self.context = context
        self._collected_at_override = settings.optional_timestamp("collected_at")

    def collected_at(self, from_source: datetime | None = None) -> datetime:
        """Resolve the observation time.

        Order: the ``collected_at`` setting, then a timestamp embedded in the source data,
        then the clock. File modification times are deliberately never used: they change on
        copy/clone and are not evidence of when an export was taken.
        """
        if self._collected_at_override is not None:
            return self._collected_at_override
        if from_source is not None:
            return from_source
        return self.context.clock()

    def relpath(self, path: Path) -> str:
        """Render ``path`` relative to the config directory for the ``origin`` field."""
        try:
            return path.resolve().relative_to(self.context.base_dir.resolve()).as_posix()
        except ValueError:
            return path.name

    def evidence(
        self,
        kind: str,
        subject: str,
        data: Mapping[str, Any],
        origin: str,
        collected_at: datetime,
        **extra: Any,
    ) -> Evidence:
        return Evidence(
            kind=kind,
            subject=subject,
            source=self.name,
            collected_at=collected_at,
            data=dict(data),
            origin=origin,
            **extra,
        )

    @abstractmethod
    def collect(self) -> list[Evidence]:
        """Read the source and return normalized evidence records."""


_REGISTRY: dict[str, type[Collector]] = {}


def register_collector[C: type[Collector]](cls: C) -> C:
    """Class decorator that makes a collector available by its ``type_name``."""
    name = getattr(cls, "type_name", None)
    if not name:
        raise TypeError(f"{cls.__name__} must define type_name")
    existing = _REGISTRY.get(name)
    if existing is not None and existing is not cls:
        raise ValueError(f"collector type {name!r} already registered by {existing.__name__}")
    _REGISTRY[name] = cls
    return cls


@cache
def _load_entry_points() -> None:
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            cls = ep.load()
        except Exception as exc:  # a broken plugin must not take down the built-ins
            log.warning("could not load collector plugin %s: %s", ep.name, exc)
            continue
        if isinstance(cls, type) and issubclass(cls, Collector):
            register_collector(cls)
        else:
            log.warning("collector plugin %s is not a Collector subclass; ignored", ep.name)


def collector_types() -> dict[str, type[Collector]]:
    _load_entry_points()
    return dict(sorted(_REGISTRY.items()))


def build_collector(settings: Settings, context: CollectorContext) -> Collector:
    """Instantiate the collector described by one ``collectors[]`` config entry."""
    name = settings.text("name")
    type_name = settings.text("type")
    cls = collector_types().get(type_name)
    if cls is None:
        known = ", ".join(collector_types())
        raise ConfigError(
            f"{settings.where}: unknown collector type {type_name!r} (known: {known})"
        )
    try:
        return cls(name, settings, context)
    except CollectorError as exc:
        raise ConfigError(f"{settings.where}: {exc}") from exc


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise CollectorError(f"cannot read {path}: {exc.strerror or exc}") from exc
