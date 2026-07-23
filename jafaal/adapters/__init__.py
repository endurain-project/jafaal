"""Batteries-included reference adapters for JAFAAL's host-implemented ports.

The JAFAAL core depends only on the ports/protocols (:mod:`jafaal.ports`,
:mod:`jafaal.state_store`); these ready-made adapters let a host wire a working
deployment with minimal code and can be swapped for custom implementations at
any time.

They are intentionally **not** imported by ``import jafaal`` — import them
explicitly from ``jafaal.adapters`` — so the core stays free of their (optional)
dependencies and the dependency direction only ever points *inward*
(adapters → core), never the reverse.

Provided:

* :class:`~jafaal.adapters.sqlalchemy_user_repository.SqlAlchemyUserRepository`
  — a generic ``UserRepository`` over the host's user model (mapped via
  :func:`jafaal.map_models`).
* :class:`~jafaal.adapters.static_settings.StaticSettingsProvider` — a
  ``SettingsProvider`` backed by in-code constants (the simple, non-DB
  password-policy / sign-up-config mode).
* :class:`~jafaal.adapters.event_sinks.LoggingAuthEventSink` /
  :class:`~jafaal.adapters.event_sinks.CompositeAuthEventSink` — reference
  ``AuthEventSink`` implementations (log events / fan out to several sinks).
* :class:`~jafaal.adapters.redis_state_store.RedisStateStore` — a distributed
  ``StateStore`` (lockout + TOTP-replay state shared across workers/replicas);
  requires the ``jafaal[redis]`` extra.

Install and wire, for example::

    import jafaal
    from jafaal.adapters import (
        SqlAlchemyUserRepository,
        StaticSettingsProvider,
        LoggingAuthEventSink,
    )

    jafaal.configure_user_repository(SqlAlchemyUserRepository())
    jafaal.configure_settings_provider(StaticSettingsProvider())
    jafaal.configure_event_sink(LoggingAuthEventSink())
"""

from __future__ import annotations

from jafaal.adapters.event_sinks import CompositeAuthEventSink, LoggingAuthEventSink
from jafaal.adapters.redis_state_store import RedisStateStore
from jafaal.adapters.sqlalchemy_user_repository import SqlAlchemyUserRepository
from jafaal.adapters.static_settings import (
    DEFAULT_PASSWORD_POLICY,
    DEFAULT_SIGNUP_CONFIG,
    StaticSettingsProvider,
)

__all__ = [
    "DEFAULT_PASSWORD_POLICY",
    "DEFAULT_SIGNUP_CONFIG",
    "CompositeAuthEventSink",
    "LoggingAuthEventSink",
    "RedisStateStore",
    "SqlAlchemyUserRepository",
    "StaticSettingsProvider",
]
