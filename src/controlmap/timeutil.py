"""Date/time helpers. All timestamps inside controlmap are timezone-aware UTC."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, date, datetime, time

from .errors import ControlmapError

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    """Return the current time, honouring SOURCE_DATE_EPOCH for reproducible builds."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=UTC)
        except ValueError as exc:
            raise ControlmapError(f"SOURCE_DATE_EPOCH is not an integer: {epoch!r}") from exc
    return datetime.now(tz=UTC)


def parse_datetime(value: object, *, field: str = "timestamp") -> datetime:
    """Parse an ISO-8601 date or datetime (or a YAML-decoded one) into an aware UTC datetime.

    Naive values are interpreted as UTC. A bare date means midnight UTC on that day.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime.combine(value, time.min)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ControlmapError(f"{field}: empty timestamp")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ControlmapError(f"{field}: not an ISO-8601 timestamp: {value!r}") from exc
    else:
        raise ControlmapError(f"{field}: expected a timestamp, got {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_date(value: object, *, field: str = "date") -> date:
    """Parse an ISO-8601 date (a datetime is truncated to its UTC date)."""
    if isinstance(value, datetime):
        return parse_datetime(value, field=field).date()
    if isinstance(value, date):
        return value
    return parse_datetime(value, field=field).date()


def optional_date(value: object, *, field: str = "date") -> date | None:
    """Like parse_date, but empty strings and None mean "no date"."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return parse_date(value, field=field)


def end_of_day(day: date) -> datetime:
    """The last representable instant of ``day`` in UTC (used as the evaluation cut-off)."""
    return datetime.combine(day, time.max, tzinfo=UTC)


def isoformat(dt: datetime) -> str:
    """Serialise an aware datetime as a compact ISO-8601 UTC string with a Z suffix."""
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
