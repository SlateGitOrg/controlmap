"""Project configuration (``controlmap.yaml``) and the collect/evaluate workflow.

Example::

    company: Acme Cloud, Inc.
    store: .controlmap/store
    library: library/controls.yaml
    exceptions: exceptions.yaml
    as_of: 2026-10-01            # optional default evaluation date
    collectors:
      - {name: okta, type: idp_csv, path: data/idp/users.csv, tenant: acme}

All relative paths are resolved against the directory containing the configuration file.
String values may reference environment variables as ``${NAME}`` or ``${NAME:-default}``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .collectors import CollectorContext, build_collector
from .collectors.http import Transport, UrllibTransport
from .engine import evaluate
from .errors import ConfigError, ControlmapError
from .exceptions import ExceptionRegister, load_exceptions
from .library import Library, load_library
from .model import EvaluationRun, Evidence
from .settings import Settings, load_yaml
from .store import CollectionRun, EvidenceStore
from .timeutil import Clock, utc_now

log = logging.getLogger(__name__)

CONFIG_KEYS = frozenset({"company", "store", "library", "exceptions", "as_of", "collectors"})


@dataclass(frozen=True)
class ProjectConfig:
    path: Path
    company: str
    store_path: Path
    library_path: Path
    exceptions_path: Path | None
    default_as_of: date | None
    collectors: tuple[Settings, ...]

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    def store(self) -> EvidenceStore:
        return EvidenceStore(self.store_path)


def load_config(path: Path) -> ProjectConfig:
    doc = Settings(load_yaml(path, ConfigError), path.name, ConfigError, path.parent)
    doc.reject_unknown(CONFIG_KEYS)
    collectors = tuple(doc.items("collectors"))
    names = [c.text("name") for c in collectors]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"{path.name}: duplicate collector name(s) {', '.join(duplicates)}")
    return ProjectConfig(
        path=path,
        company=doc.text("company"),
        store_path=doc.path("store") if doc.has("store") else path.parent / ".controlmap/store",
        library_path=doc.path("library"),
        exceptions_path=doc.optional_path("exceptions"),
        default_as_of=doc.optional_day("as_of"),
        collectors=collectors,
    )


@dataclass
class CollectorReport:
    name: str
    type: str
    records: int = 0
    new: int = 0
    error: str | None = None


@dataclass
class CollectReport:
    collectors: list[CollectorReport] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.error is None for c in self.collectors)

    @property
    def total_new(self) -> int:
        return sum(c.new for c in self.collectors)


def collect(
    config: ProjectConfig,
    *,
    only: set[str] | None = None,
    clock: Clock = utc_now,
    transport_factory: Callable[[], Transport] = UrllibTransport,
    fail_fast: bool = False,
) -> CollectReport:
    """Run the configured collectors and store their evidence.

    A failing collector is reported and the others continue (unless ``fail_fast``), so one
    broken export does not block refreshing the rest of the evidence. Each successful run is
    recorded as a :class:`CollectionRun` so subjects a source stops reporting are retired.
    """
    context = CollectorContext(
        base_dir=config.base_dir,
        clock=clock,
        transport_factory=transport_factory,
        environ=dict(os.environ),
    )
    selected = [s for s in config.collectors if only is None or s.text("name") in only]
    if only:
        unknown = sorted(only - {s.text("name") for s in config.collectors})
        if unknown:
            raise ConfigError(f"no collector named {', '.join(unknown)}")
    collectors = [build_collector(settings, context) for settings in selected]
    store = config.store()
    report = CollectReport()
    for collector in collectors:
        entry = CollectorReport(collector.name, collector.type_name)
        report.collectors.append(entry)
        try:
            records = collector.collect()
            results = store.put_many(records)
            store.put_run(CollectionRun.from_records(collector.name, records, clock()))
        except ControlmapError as exc:
            entry.error = str(exc)
            log.error("collector %s failed: %s", collector.name, exc)
            if fail_fast:
                raise
            continue
        entry.records = len(results)
        entry.new = sum(1 for r in results if r.created)
        log.info("collector %s: %d records (%d new)", collector.name, entry.records, entry.new)
    return report


@dataclass(frozen=True)
class Evaluation:
    config: ProjectConfig
    library: Library
    register: ExceptionRegister
    run: EvaluationRun
    records: tuple[Evidence, ...]


def evaluate_project(config: ProjectConfig, as_of: date | None = None) -> Evaluation:
    """Load the library and exception register and evaluate stored evidence."""
    as_of = as_of or config.default_as_of or utc_now().date()
    library = load_library(config.library_path)
    for warning in library.warnings:
        log.warning("library: %s", warning)
    register = load_exceptions(config.exceptions_path, library)
    records = tuple(config.store())
    if not records:
        raise ControlmapError(
            f"the evidence store {config.store_path} is empty; run 'controlmap collect' first"
        )
    runs = config.store().runs()
    run = evaluate(library, records, register, as_of, config.company, runs=runs)
    return Evaluation(config, library, register, run, records)
