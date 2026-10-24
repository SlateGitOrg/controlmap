"""Built-in collectors. Importing this package registers them."""

from . import cloud, endpoints, github, hris, idp, manual
from .base import (
    Collector,
    CollectorContext,
    build_collector,
    collector_types,
    register_collector,
)

__all__ = [
    "Collector",
    "CollectorContext",
    "build_collector",
    "cloud",
    "collector_types",
    "endpoints",
    "github",
    "hris",
    "idp",
    "manual",
    "register_collector",
]
