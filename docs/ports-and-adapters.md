# Ports & Adapters

JAFAAL owns the security-critical core (tokens, sessions, credentials, MFA, scope
checks). The concerns that are inherently the *application's* are provided by the
host through a small set of **ports** (protocols). The library depends only on
these interfaces — never on a specific application — so you can swap any
implementation.

## The ports you implement

Install each adapter once at startup; every component reads it through the
matching `get_*` accessor.

### `UserRepository`

Host-owned persistence for the user table. Methods run inside the caller's
transaction and take the active SQLAlchemy `Session`.

```python
from jafaal import UserProtocol, configure_user_repository


class SqlUserRepository:
    def get_by_id(self, user_id, db) -> UserProtocol | None: ...
    def get_by_email(self, email, db) -> UserProtocol | None: ...
    def get_by_username(self, username, db) -> UserProtocol | None: ...
    def create_local_user(self, username, email, db, *, is_active, is_verified) -> UserProtocol: ...
    def provision_from_idp(self, identity, db) -> UserProtocol: ...  # SSO auto-provisioning
    def sync_from_idp(self, user_id, claims, db) -> None: ...  # optional profile sync
    def set_email_verified(self, user_id, db, *, activate) -> None: ...


configure_user_repository(SqlUserRepository())
```

JAFAAL never reads app-specific profile fields — only `id`, `username`, `email`,
`is_active`, `is_superuser`, `is_verified`, and the `mfa_enabled` property (see
[`UserProtocol`][jafaal.UserProtocol]).

### `SettingsProvider`

Host-owned dynamic settings: the password policy and the sign-up toggles.

```python
from jafaal import PasswordPolicy, SignupConfig, configure_settings_provider


class MySettings:
    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(min_length_regular=15, min_length_admin=20, password_type="length_only")

    def get_signup_config(self) -> SignupConfig:
        return SignupConfig(enabled=True, require_email_verification=False, require_admin_approval=False)


configure_settings_provider(MySettings())
```

### `AuthEventSink`

JAFAAL performs the security-critical work (mint/hash/store token, single-use +
expiry, enumeration-safe response) and **emits an event**; the host delivers it
(email, SMS, websocket, queue, or just a log). This keeps email templates and
i18n entirely out of the auth core.

The emitted events are [`PasswordResetRequested`][jafaal.PasswordResetRequested],
[`EmailVerificationRequested`][jafaal.EmailVerificationRequested],
[`SignupPendingAdminApproval`][jafaal.SignupPendingAdminApproval] and
[`SignupApproved`][jafaal.SignupApproved]. Each reset/verification event carries
the plaintext `token` for you to build and send the link.

```python
from jafaal import configure_event_sink


class EmailEventSink:
    async def on_password_reset_requested(self, event) -> None:
        send_email(event.email, reset_link(event.token))  # your delivery

    async def on_email_verification_requested(self, event) -> None: ...
    async def on_signup_pending_admin_approval(self, event) -> None: ...
    async def on_signup_approved(self, event) -> None: ...


configure_event_sink(EmailEventSink())
```

Delivery is best-effort: for the enumeration-safe reset/verify flows, failures
are swallowed and logged so they can never change the HTTP response or leak
whether an account exists. If you skip these flows, the default
[`NullAuthEventSink`][jafaal.NullAuthEventSink] is a no-op.

### `PasswordBreachChecker`

Optionally screen a proposed password against a breach corpus / blocklist during
sign-up and password change (NIST SP 800-63B, the recommended companion to a
`length_only` policy). The port is one method that returns whether the password
should be rejected:

```python
from jafaal import configure_password_breach_checker


class MyChecker:
    def is_breached(self, password: str) -> bool:
        return password in my_local_blocklist


configure_password_breach_checker(MyChecker())
```

It is consulted **after** the length/complexity policy passes and **before**
hashing, runs synchronously in the request path (keep it fast), and should fail
open (return `False` on an upstream error). It checks the *password alone* — not
a username/email pair. The default
[`NullPasswordBreachChecker`][jafaal.NullPasswordBreachChecker] disables
screening; ready-made adapters are [below](#hibpbreachchecker-blocklistbreachchecker).

## Batteries-included adapters

Ready-made implementations live in `jafaal.adapters`. They are **not** imported
by `import jafaal` (so the core never pulls their optional dependencies); import
them explicitly. The core depends only on the ports, so any adapter is swappable.

### `SqlAlchemyUserRepository`

A generic `UserRepository` over the host's user model (mapped via
`jafaal.map_models`). The user class is auto-resolved from the registry (or pass
it explicitly).

```python
from jafaal import configure_user_repository
from jafaal.adapters import SqlAlchemyUserRepository

configure_user_repository(SqlAlchemyUserRepository())
```

Subclass and override `create_local_user` / `provision_from_idp` if your table
has extra NOT NULL columns without defaults, or `sync_from_idp` (a no-op by
default) to map refreshed IdP claims onto your profile columns.

### `StaticSettingsProvider`

A `SettingsProvider` backed by in-code constants — the simple, non-DB
password-policy / sign-up-config mode.

```python
import jafaal
from jafaal.adapters import StaticSettingsProvider

jafaal.configure_settings_provider(
    StaticSettingsProvider(
        password_policy=jafaal.PasswordPolicy(min_length_regular=16, min_length_admin=24, password_type="length_only"),
        signup_config=jafaal.SignupConfig(enabled=True, require_email_verification=True, require_admin_approval=False),
    )
)
```

### `LoggingAuthEventSink` / `CompositeAuthEventSink`

Reference `AuthEventSink` implementations: log events (the plaintext token is
**always redacted**), or fan one event out to several sinks (e.g. log *and*
email), isolating failures.

```python
import jafaal
from jafaal.adapters import CompositeAuthEventSink, LoggingAuthEventSink

jafaal.configure_event_sink(CompositeAuthEventSink([LoggingAuthEventSink(), EmailEventSink()]))
```

### `RedisStateStore`

A distributed [`StateStore`][jafaal.StateStore] that shares progressive-lockout
counters and TOTP-replay markers across workers/replicas. Requires the
`jafaal[redis]` extra.

```python
import jafaal
from jafaal.adapters import RedisStateStore

jafaal.configure_state_store(RedisStateStore(url="redis://localhost:6379/0"))
```

The client must return `bytes` (leave `decode_responses` at its default of
`False`). The tiered-lockout increment is atomic (a `WATCH`/`MULTI` transaction),
so its correctness does not depend on how many workers hit it concurrently.

### `StateStoreRateLimiter`

A batteries-included [`RateLimiter`][jafaal.RateLimiter] that enforces a
fixed-window, per-client-IP request budget using the configured
[`StateStore`][jafaal.StateStore]. It needs no extra dependency and becomes
distributed automatically once you configure
[`RedisStateStore`](#redisstatestore) — lockout, TOTP-replay, and rate-limit
counters then share one backend.

```python
import jafaal
from jafaal.adapters import StateStoreRateLimiter

jafaal.configure_rate_limiter(StateStoreRateLimiter())
# ...or: create_auth_router(rate_limiter=StateStoreRateLimiter()).
```

Budgets come from settings (`sensitive` / `write`, e.g.
`"10/minute"`), and the client IP is resolved through the proxy-aware
`trusted_proxies` logic, so set that correctly behind a reverse proxy. Rate
limiting is defense-in-depth, so the limiter **fails open** (does not block) when
the client IP is unknown, the budget is malformed, or the state store is
unavailable — an infrastructure fault must never take down authentication.

### `HibpBreachChecker` / `BlocklistBreachChecker`

Reference `PasswordBreachChecker` implementations for breached-password
screening.

`HibpBreachChecker` queries the *Have I Been Pwned* "Pwned Passwords" range API.
That endpoint is **free and unauthenticated** (no API key) and k-anonymous: the
password is SHA-1 hashed locally and only the first five hex characters of the
digest are sent, so the password (and full hash) never leave the process.
`httpx` is already a JAFAAL dependency, so no extra install is needed.

```python
import jafaal
from jafaal.adapters import HibpBreachChecker

jafaal.configure_password_breach_checker(HibpBreachChecker())
```

It **fails open** (allows the password) on any network/HTTP error so a
breach-service outage never blocks password changes. Raise `min_count` to only
reject widely-seen passwords, and pass `client=` to reuse one `httpx.Client`.

`BlocklistBreachChecker` is a dependency-free, in-memory alternative for a
bundled "top-N breached passwords" list or a custom deny-list:

```python
from jafaal.adapters import BlocklistBreachChecker

jafaal.configure_password_breach_checker(BlocklistBreachChecker(load_top_passwords()))
```

!!! note "Password-only, by design"
    Both check the *password alone*, not a username/email + password pair.
    Pair / credential-stuffing checks require a commercial service and send more
    sensitive data to a third party; JAFAAL's server-side progressive lockout
    already mitigates credential stuffing.
Per-account and per-IP progressive lockout still apply.

