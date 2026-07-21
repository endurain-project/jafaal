"""A tiny host-configuration slot used by JAFAAL's ``configure_*`` accessors.

JAFAAL delivers host-supplied adapters (user repository, settings provider, rate
limiter, state store, event sink, scope catalog, ...) through a uniform
``configure_* / get_* / reset_*`` trio backed by a process-wide singleton. This
class centralises that pattern so each module does not re-implement the
``None``-check-and-raise / reset-to-default boilerplate.

Two modes:

* **required** — construct with only a ``missing_message``. :meth:`get` raises
  :class:`RuntimeError` until :meth:`configure` installs a value (used for
  adapters JAFAAL cannot default, e.g. the user repository).
* **defaulted** — construct with a ``default_factory``. :meth:`get` always
  returns a value and :meth:`reset` restores a freshly built default (used for
  adapters with a working built-in, e.g. the in-memory state store).

The slot is a plain attribute (no locking): the contract is that hosts call
``configure`` once at startup, before serving requests — identical to the
behaviour of the module globals it replaces.
"""

from __future__ import annotations

from collections.abc import Callable

__all__ = ["ConfigSlot"]


class ConfigSlot[T]:
    """A process-wide, host-configured singleton value."""

    def __init__(
        self,
        *,
        default_factory: Callable[[], T] | None = None,
        missing_message: str = "This JAFAAL component has not been configured.",
    ) -> None:
        """Create a slot.

        Args:
            default_factory: Builds the default value. When given, the slot is
                *defaulted* (never raises); when omitted, the slot is *required*.
            missing_message: Error raised by :meth:`get` on a required slot that
                has not been configured.
        """
        self._default_factory = default_factory
        self._missing_message = missing_message
        self._value: T | None = default_factory() if default_factory is not None else None

    def configure(self, value: T) -> None:
        """Install ``value`` for the process."""
        self._value = value

    def get(self) -> T:
        """Return the installed value.

        Raises:
            RuntimeError: If a required slot has not been configured.
        """
        value = self._value
        if value is None:
            raise RuntimeError(self._missing_message)
        return value

    def is_configured(self) -> bool:
        """Return whether a value is currently installed."""
        return self._value is not None

    def reset(self) -> None:
        """Restore the default (defaulted slot) or clear the value (required slot)."""
        self._value = self._default_factory() if self._default_factory is not None else None
