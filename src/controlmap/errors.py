"""Exception hierarchy. Every error raised on purpose by controlmap derives from ControlmapError."""

from __future__ import annotations


class ControlmapError(Exception):
    """Base class for all controlmap errors."""


class ConfigError(ControlmapError):
    """The project configuration file is missing, malformed or inconsistent."""


class LibraryError(ControlmapError):
    """The control library, framework catalogs or crosswalk failed validation."""


class CollectorError(ControlmapError):
    """A collector could not read or normalize its source data."""


class EvidenceError(ControlmapError):
    """Evidence could not be stored, loaded or decoded."""


class RuleError(ControlmapError):
    """A rule was misconfigured or could not interpret its evidence."""


class ExceptionRegisterError(ControlmapError):
    """The exception register is malformed or references unknown controls/rules."""


class PackageError(ControlmapError):
    """The evidence package could not be built or read."""
