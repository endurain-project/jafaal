"""Timezone helpers shared across layers.

Kept dependency-free (stdlib only) in ``_core`` so any layer can use it without
risking an import cycle.
"""

from __future__ import annotations

from datetime import UTC, datetime


def ensure_aware_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime.

    Datetimes read back from the database may be naive depending on the backend
    and column type: PostgreSQL preserves ``tzinfo`` for ``DateTime(timezone=True)``
    columns, but SQLite (and some other drivers) drop it and return a naive value.
    Comparing such a naive value against ``datetime.now(UTC)`` in Python raises
    ``TypeError: can't compare offset-naive and offset-aware datetimes``.

    Normalizing here lets JAFAAL do Python-side timestamp comparisons portably.
    A naive value is assumed to already be in UTC (JAFAAL always persists UTC).

    Args:
        value: A timezone-aware or naive datetime.

    Returns:
        The equivalent timezone-aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
