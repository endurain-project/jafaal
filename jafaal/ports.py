"""Host-implemented ports — JAFAAL's dependency-inversion boundary.

JAFAAL owns the security-critical core (tokens, sessions, credentials, MFA,
scope checks). The concerns that are inherently the *application's* — the shape
and persistence of the user table, dynamic server settings, and how outbound
notifications (password-reset / sign-up emails, admin pings) are delivered — are
provided by the host through the protocols defined here.

The host builds concrete adapters and installs them once at startup
(:func:`configure_user_repository` / :func:`configure_settings_provider` /
:func:`configure_event_sink`); every JAFAAL component reads them through the
matching ``get_*`` accessor. This mirrors the :class:`~jafaal.settings.AuthSettings`
config-delivery pattern (``jafaal.configure`` / ``get_settings``): the library
depends only on these interfaces, never on a specific application.

Value types that cross the boundary (:class:`IdpIdentity`, :class:`SignupConfig`,
:class:`PasswordPolicy`, and the event dataclasses) are plain frozen dataclasses
— framework-agnostic, like :class:`jafaal.principal.Principal`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from jafaal._core.registry import ConfigSlot

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ===========================================================================
# User boundary
# ===========================================================================


@runtime_checkable
class UserProtocol(Protocol):
    """The user attributes JAFAAL reads across the boundary.

    Satisfied by a host user model built on :class:`jafaal.UserMixin`: ``id``,
    ``username``, ``email``, ``is_active``, ``is_verified``, and the
    ``mfa_enabled`` property. JAFAAL never reads app-specific profile fields.

    ``is_superuser`` is deliberately **not** here. It is an authorisation
    concept, and authorisation is the host's domain: it is read only by the
    default :class:`TieredScopeResolver`, which is one swappable implementation
    of the :class:`ScopeResolver` port. A host whose model has no such flag —
    because it uses roles, organisations, or per-tenant grants — supplies its own
    resolver and never needs the column. Requiring it on the protocol would have
    made a two-tier authorisation model a condition of using the library.
    """

    id: Any
    username: str
    email: str
    is_active: bool
    is_verified: bool

    @property
    def mfa_enabled(self) -> bool: ...


def is_superuser(user: UserProtocol) -> bool:
    """Read the optional ``is_superuser`` flag from a host user model.

    The single place JAFAAL touches that attribute, so a host model without it
    simply reads as non-privileged everywhere instead of raising in whichever
    code path happens to look first. Authorisation proper belongs to the
    :class:`ScopeResolver` port; this flag only feeds the two conveniences that
    predate it (the default resolver's tiers and the admin password-length
    policy).

    Args:
        user: The host user object.

    Returns:
        ``True`` when the model defines a truthy ``is_superuser``.
    """
    return bool(getattr(user, "is_superuser", False))


@dataclass(frozen=True)
class IdpIdentity:
    """An identity resolved from an external identity provider.

    Handed to the host so it can provision (or sync) its own user row with its
    own profile shape/defaults. ``claims`` carries the raw mapped IdP claims so
    the host can pick whatever additional fields it wants.
    """

    subject: str
    idp_id: int
    email: str | None
    email_verified: bool
    suggested_username: str
    display_name: str | None
    claims: Mapping[str, Any]


class UserRepository(Protocol):
    """Host-owned persistence for the user table.

    Methods run inside the caller's transaction and therefore take the active
    :class:`~sqlalchemy.orm.Session`. Implementations return objects satisfying
    :class:`UserProtocol` (typically the host's ``Users`` ORM instance).
    """

    def get_by_id(self, user_id: Any, db: Session) -> UserProtocol | None:
        """Return the user with ``user_id``, or ``None``."""
        ...

    def get_by_email(self, email: str, db: Session) -> UserProtocol | None:
        """Return the user with ``email``, or ``None``."""
        ...

    def get_by_username(self, username: str, db: Session) -> UserProtocol | None:
        """Return the user with ``username``, or ``None``."""
        ...

    def create_local_user(
        self,
        username: str,
        email: str,
        db: Session,
        *,
        is_active: bool,
        is_verified: bool,
    ) -> UserProtocol:
        """Create a user row for a local sign-up and return it.

        JAFAAL validates the password and persists the credential separately in
        its own ``users_local_credentials`` table; the host only creates the
        user/profile row here (with the given active/verified state and any
        host-specific defaults). ``username``/``email`` are passed as supplied;
        the host applies its own normalization and uniqueness checks.

        **Flush, do not commit.** The primary key must be populated for the
        credential write that follows, but the two rows have to land in one
        transaction: committing here leaves a credential-less account squatting
        the username and email if anything downstream fails. JAFAAL commits both
        together when it writes the credential.
        """
        ...

    def provision_from_idp(self, identity: IdpIdentity, db: Session) -> UserProtocol:
        """Create a user row from an IdP identity and return it.

        The account has no local password (JAFAAL persists no credential).
        Profile shape and defaults are the host's concern. Flush to populate the
        primary key, but do not commit: JAFAAL creates the identity-provider link
        in the same caller-owned transaction.
        """
        ...

    def sync_from_idp(self, user_id: Any, claims: Mapping[str, Any], db: Session) -> None:
        """Optionally sync host-owned profile fields from refreshed IdP claims.

        ``claims`` is the mapped IdP claim dict (e.g. ``email``, ``name``), plus
        ``email_verified`` so the host can apply its own policy. Called on
        subsequent logins when IdP→user sync is enabled; the host decides which
        fields to update and resolves any email conflicts.

        ``email`` is present **only when the provider asserted it verified** —
        JAFAAL withholds an unverified address rather than hand the host
        something it might write onto the user row, since the local email is
        where password resets are delivered.
        """
        ...

    def set_email_verified(self, user_id: Any, db: Session, *, activate: bool) -> None:
        """Mark the user's email address as verified.

        When ``activate`` is ``True`` the account is also activated (used when
        email verification is the last gate before login); when ``False`` the
        account stays inactive (e.g. admin approval is still pending). Flush,
        but do not commit; token consumption and this update are one transaction.
        """
        ...


# ===========================================================================
# Server-settings boundary
# ===========================================================================


@dataclass(frozen=True)
class PasswordPolicy:
    """Minimum-length policy resolved by user tier, plus the policy type."""

    min_length_regular: int
    min_length_admin: int
    password_type: str

    def min_length_for(self, *, is_superuser: bool) -> int:
        """Return the minimum length for an admin/superuser or regular account."""
        return self.min_length_admin if is_superuser else self.min_length_regular


@dataclass(frozen=True)
class SignupConfig:
    """Host sign-up toggles."""

    enabled: bool
    require_email_verification: bool
    require_admin_approval: bool


class SettingsProvider(Protocol):
    """Host-owned dynamic settings (password policy + sign-up toggles).

    Read-only configuration, independent of the caller's transaction, so these
    methods take no session — a DB-backed adapter manages its own read (JAFAAL's
    :func:`jafaal.orm.session_scope` is available) and a static adapter simply
    returns constants.
    """

    def get_password_policy(self) -> PasswordPolicy:
        """Return the active password policy."""
        ...

    def get_signup_config(self) -> SignupConfig:
        """Return the active sign-up configuration."""
        ...


# ===========================================================================
# Outbound-events boundary (email / notifications)
# ===========================================================================


@dataclass(frozen=True)
class PasswordResetRequested:
    """A password reset was requested; deliver ``token`` to ``email``."""

    user_id: Any
    email: str
    display_name: str | None
    token: str
    expires_at: datetime
    locale: str | None


@dataclass(frozen=True)
class EmailVerificationRequested:
    """A sign-up needs email verification; deliver ``token`` to ``email``."""

    user_id: Any
    email: str
    display_name: str | None
    token: str
    expires_at: datetime
    locale: str | None


@dataclass(frozen=True)
class SignupPendingAdminApproval:
    """A newly verified sign-up is awaiting admin approval.

    JAFAAL emits one event with the new user's context; the host fans out to
    whichever admins it wants, in whatever locale.
    """

    user_id: Any
    username: str
    display_name: str | None


@dataclass(frozen=True)
class SignupApproved:
    """A pending sign-up was approved; notify the user."""

    user_id: Any
    email: str
    display_name: str | None
    locale: str | None


@dataclass(frozen=True)
class NewDeviceLogin:
    """A user signed in from a device/browser not seen on any prior session.

    Emitted best-effort after a successful login so the host can alert the user
    ("new sign-in from …"). ``device_description`` is a human-readable summary
    parsed from the User-Agent (browser + OS).
    """

    user_id: Any
    username: str
    ip: str | None
    device_description: str
    session_id: str


@dataclass(frozen=True)
class AccountLocked:
    """Progressive lockout was applied to a login / MFA / step-up subject.

    Emitted best-effort when a lockout tier trips so the host can notify the
    account owner. ``subject`` is the locked value (a username or an IP address),
    ``subject_kind`` distinguishes the two, and ``store`` names the flow
    (``"Login"`` / ``"MFA"`` / ``"Step-up"``).
    """

    subject: str
    subject_kind: str
    store: str
    failed_attempts: int
    lockout_label: str


@dataclass(frozen=True)
class RefreshTokenTheftDetected:
    """A rotated refresh token was replayed past the grace window (likely theft).

    Emitted when reuse detection invalidates a token family, so the host can
    force a re-login notification / security alert for the affected user.
    """

    user_id: Any
    token_family_id: str


@dataclass(frozen=True)
class IdpAccountLinked:
    """An identity provider was linked to an existing account by matching email.

    Emitted when an SSO login adopts a pre-existing local account rather than
    creating one — a new way to sign in that the owner did not initiate from a
    session they already held. Tell them out of band, so a link they did not
    expect is visible rather than silent.
    """

    user_id: Any
    username: str
    idp_name: str
    idp_slug: str
    email: str


@dataclass(frozen=True)
class AuthenticatorChanged:
    """An authentication factor was added to or removed from an account.

    Covers TOTP enable/disable, backup-code regeneration, and passkey
    registration/deletion. Binding or unbinding an authenticator changes *how
    the account can be signed into*, so the owner has to hear about it out of
    band — an attacker who enrols their own factor (or strips the victim's)
    otherwise does so in total silence. ``remaining_factors`` lets a host warn
    loudly when an account is left with none.
    """

    user_id: Any
    username: str
    #: ``"totp"``, ``"backup_codes"``, or ``"passkey"``.
    factor: str
    #: ``"added"`` or ``"removed"``.
    change: str
    remaining_factors: int | None = None


class AuthEventSink(Protocol):
    """Host-owned delivery of JAFAAL's outbound notifications.

    JAFAAL performs the security-critical work (mint/hash/store token,
    single-use + expiry, enumeration-safe response) and emits these events; the
    host delivers them via email/SMS/websocket/queue/log. All methods are
    awaited best-effort — for enumeration-safe flows JAFAAL swallows and logs
    delivery failures so they cannot change the HTTP response or leak whether an
    account exists.
    """

    async def on_password_reset_requested(self, event: PasswordResetRequested) -> None: ...

    async def on_email_verification_requested(self, event: EmailVerificationRequested) -> None: ...

    async def on_signup_pending_admin_approval(self, event: SignupPendingAdminApproval) -> None: ...

    async def on_signup_approved(self, event: SignupApproved) -> None: ...

    # --- Security events (best-effort, fire-and-forget) ---
    # Emitted from the auth flow via jafaal.ports.dispatch_event / adispatch_event,
    # which skip a sink that does not implement the method — so a host sink written
    # before these existed keeps working without change.

    async def on_new_device_login(self, event: NewDeviceLogin) -> None: ...

    async def on_account_locked(self, event: AccountLocked) -> None: ...

    async def on_refresh_token_theft_detected(self, event: RefreshTokenTheftDetected) -> None: ...

    async def on_idp_account_linked(self, event: IdpAccountLinked) -> None: ...

    async def on_authenticator_changed(self, event: AuthenticatorChanged) -> None: ...


class NullAuthEventSink:
    """Default no-op sink — a host that skips these flows implements nothing."""

    async def on_password_reset_requested(self, event: PasswordResetRequested) -> None:
        return None

    async def on_email_verification_requested(self, event: EmailVerificationRequested) -> None:
        return None

    async def on_signup_pending_admin_approval(self, event: SignupPendingAdminApproval) -> None:
        return None

    async def on_signup_approved(self, event: SignupApproved) -> None:
        return None

    async def on_new_device_login(self, event: NewDeviceLogin) -> None:
        return None

    async def on_account_locked(self, event: AccountLocked) -> None:
        return None

    async def on_refresh_token_theft_detected(self, event: RefreshTokenTheftDetected) -> None:
        return None

    async def on_idp_account_linked(self, event: IdpAccountLinked) -> None:
        return None

    async def on_authenticator_changed(self, event: AuthenticatorChanged) -> None:
        return None


# ===========================================================================
# Scope-resolution boundary
# ===========================================================================


@runtime_checkable
class ScopeResolver(Protocol):
    """Host-owned mapping from a user to the scopes their tokens carry.

    JAFAAL's default (:class:`TieredScopeResolver`) is deliberately simple: two
    tiers, keyed on ``is_superuser``. That covers the common case and nothing
    else — it cannot express "this user is a billing admin", per-organisation
    roles, or any grant that is not a boolean on the user row. Authorisation
    models are application domain, not authentication plumbing, so the mapping is
    a port: implement it and JAFAAL stamps whatever scopes you return into the
    tokens it mints.

    The resolver runs at token issuance (login, refresh, SSO/PKCE exchange), and
    again per request when
    :attr:`~jafaal.settings.AuthSettings.reauthorize_scopes_per_request` is set —
    where the result is *intersected* with the token's existing scopes, so
    re-resolution can only ever narrow a live token's authority, never widen it.

    Keep it fast and side-effect free; it is on the login path. It is called with
    the user alone — a resolver that needs more (roles from another table, say)
    should read them through its own session or cache rather than expect one to
    be passed in, since JAFAAL calls it from several transaction contexts.
    """

    def scopes_for(self, user: UserProtocol) -> tuple[str, ...]:
        """Return the scopes to stamp into ``user``'s tokens."""
        ...


class TieredScopeResolver:
    """Default resolver: the :class:`~jafaal.scopes.ScopeCatalog`'s two tiers.

    Returns the catalog's ``admin`` tuple for a user whose ``is_superuser``
    attribute is truthy and ``regular`` otherwise. A model without that attribute
    gets ``regular``, so the two-tier default is a *convenience* rather than a
    schema requirement — the host adds the column if it wants the split, or
    installs its own resolver if its authorisation model is richer than a
    boolean.
    """

    def scopes_for(self, user: UserProtocol) -> tuple[str, ...]:
        """Return the catalog tier matching the user's superuser flag."""
        import jafaal.scopes as jafaal_scopes

        catalog = jafaal_scopes.get_scope_catalog()
        return catalog.admin if is_superuser(user) else catalog.regular


# ===========================================================================
# Password-breach boundary
# ===========================================================================


@runtime_checkable
class PasswordBreachChecker(Protocol):
    """Host-owned check for whether a password appears in a breach corpus/blocklist.

    Consulted during sign-up and password change after NFC normalization and the
    length/complexity policy, before hashing. Return ``True`` to reject the
    password. JAFAAL calls it with the NFC password and, when distinct, an NFKC
    compatibility projection to prevent blocklist alias bypasses.

    It runs synchronously in the request path, so keep it fast. A network-backed
    checker may return ``False`` on an upstream error for availability, but that
    makes NIST blocklist alignment conditional during the outage.
    """

    def is_breached(self, password: str) -> bool: ...


class NullPasswordBreachChecker:
    """Default checker that treats every password as not breached (no-op)."""

    def is_breached(self, password: str) -> bool:
        return False


# ===========================================================================
# Installed-adapter accessors (mirror jafaal.settings.configure/get_settings)
# ===========================================================================

_user_repository: ConfigSlot[UserRepository] = ConfigSlot(
    missing_message=(
        "JAFAAL has no UserRepository configured. Call jafaal.configure_user_repository(...) at application startup."
    )
)
_settings_provider: ConfigSlot[SettingsProvider] = ConfigSlot(
    missing_message=(
        "JAFAAL has no SettingsProvider configured. Call "
        "jafaal.configure_settings_provider(...) at application startup."
    )
)
_event_sink: ConfigSlot[AuthEventSink] = ConfigSlot(default_factory=NullAuthEventSink)
_password_breach_checker: ConfigSlot[PasswordBreachChecker] = ConfigSlot(default_factory=NullPasswordBreachChecker)
_scope_resolver: ConfigSlot[ScopeResolver] = ConfigSlot(default_factory=TieredScopeResolver)


def configure_user_repository(repository: UserRepository) -> None:
    """Install the host's :class:`UserRepository`. Call once at startup."""
    _user_repository.configure(repository)


def get_user_repository() -> UserRepository:
    """Return the installed :class:`UserRepository`.

    Raises:
        RuntimeError: If none has been configured.
    """
    return _user_repository.get()


def is_user_repository_configured() -> bool:
    """Return whether a :class:`UserRepository` has been installed."""
    return _user_repository.is_configured()


def configure_settings_provider(provider: SettingsProvider) -> None:
    """Install the host's :class:`SettingsProvider`. Call once at startup."""
    _settings_provider.configure(provider)


def get_settings_provider() -> SettingsProvider:
    """Return the installed :class:`SettingsProvider`.

    Raises:
        RuntimeError: If none has been configured.
    """
    return _settings_provider.get()


def is_settings_provider_configured() -> bool:
    """Return whether a :class:`SettingsProvider` has been installed."""
    return _settings_provider.is_configured()


def configure_event_sink(sink: AuthEventSink) -> None:
    """Install the host's :class:`AuthEventSink` (defaults to a no-op sink)."""
    _event_sink.configure(sink)


def get_event_sink() -> AuthEventSink:
    """Return the installed :class:`AuthEventSink` (``NullAuthEventSink`` by default)."""
    return _event_sink.get()


def configure_password_breach_checker(checker: PasswordBreachChecker) -> None:
    """Install the host's :class:`PasswordBreachChecker` (defaults to a no-op)."""
    _password_breach_checker.configure(checker)


def get_password_breach_checker() -> PasswordBreachChecker:
    """Return the installed :class:`PasswordBreachChecker` (no-op by default)."""
    return _password_breach_checker.get()


def configure_scope_resolver(resolver: ScopeResolver) -> None:
    """Install the host's :class:`ScopeResolver`.

    Call once at startup, before tokens are issued. Defaults to
    :class:`TieredScopeResolver` (the ``is_superuser`` two-tier mapping).

    Args:
        resolver: The host's scope-resolution adapter.
    """
    _scope_resolver.configure(resolver)


def get_scope_resolver() -> ScopeResolver:
    """Return the installed :class:`ScopeResolver` (:class:`TieredScopeResolver` by default)."""
    return _scope_resolver.get()


def _log_event_failure(method_name: str, err: BaseException) -> None:
    """Log a swallowed :class:`AuthEventSink` delivery failure."""
    logger.warning("AuthEventSink %s failed: %s", method_name, type(err).__name__, exc_info=err)


EVENT_DISPATCH_TIMEOUT_SECONDS: Final = 10.0
"""Hard cap on a single :class:`AuthEventSink` delivery before it is abandoned.

A sink is host code doing I/O (SMTP, webhooks, a SIEM push). Without a deadline a
hung remote turns every login into a leaked worker.
"""

MAX_INFLIGHT_EVENTS: Final = 256
"""Backpressure bound on concurrently in-flight event deliveries.

Events are fired on the auth hot path, so an unbounded queue would let a slow
sink convert a login flood into unbounded memory growth. Past this many pending
deliveries new events are dropped and logged rather than accumulated.
"""

CRITICAL_EVENT_METHODS: frozenset[str] = frozenset(
    {
        "on_account_locked",
        "on_refresh_token_theft_detected",
        "on_idp_account_linked",
        "on_authenticator_changed",
    }
)
"""Events whose loss is itself a security incident.

An undelivered "your account was locked", "refresh-token theft detected", or
"a new identity provider can now sign in as you" notification is not a missed
convenience email — it is the signal a user or operator needs to react to an
attack in progress. A flood of ordinary notifications must therefore never be
able to starve them out, so these are admitted against
:data:`MAX_INFLIGHT_CRITICAL_EVENTS` (strictly larger than the general bound),
which reserves headroom that routine traffic cannot consume.
"""

MAX_INFLIGHT_CRITICAL_EVENTS: Final = 1024
"""Backpressure bound applied to :data:`CRITICAL_EVENT_METHODS` deliveries.

Still bounded — an unbounded queue is a memory-exhaustion lever whatever the
event — but four times the general limit, so routine notifications saturating
:data:`MAX_INFLIGHT_EVENTS` still leave room for a security signal. Dropping one
is logged at ``ERROR`` (not ``WARNING``) so it surfaces as an operational fault.
"""

_dispatch_state = threading.Condition()
_inflight_events = 0
_dispatch_loop: asyncio.AbstractEventLoop | None = None


def _acquire_dispatch_slot(method_name: str) -> bool:
    """Reserve one in-flight slot, or return ``False`` when the bound is reached.

    Security-critical events (:data:`CRITICAL_EVENT_METHODS`) are admitted
    against the larger :data:`MAX_INFLIGHT_CRITICAL_EVENTS` ceiling, so a burst
    of routine notifications cannot starve out a lockout or token-theft alert.

    Args:
        method_name: The sink method about to be invoked.

    Returns:
        ``True`` when a slot was reserved.
    """
    global _inflight_events
    limit = MAX_INFLIGHT_CRITICAL_EVENTS if method_name in CRITICAL_EVENT_METHODS else MAX_INFLIGHT_EVENTS
    with _dispatch_state:
        if _inflight_events >= limit:
            return False
        _inflight_events += 1
        return True


def _release_dispatch_slot(_result: object = None) -> None:
    """Return an in-flight slot and wake anyone draining the queue."""
    global _inflight_events
    with _dispatch_state:
        _inflight_events -= 1
        if _inflight_events == 0:
            _dispatch_state.notify_all()


def _get_dispatch_loop() -> asyncio.AbstractEventLoop:
    """Return the shared dispatch loop, starting its daemon thread on first use."""
    global _dispatch_loop
    with _dispatch_state:
        loop = _dispatch_loop
        if loop is not None and not loop.is_closed():
            return loop
        loop = asyncio.new_event_loop()
        threading.Thread(
            target=_run_dispatch_loop,
            args=(loop,),
            name="jafaal-event-dispatch",
            daemon=True,
        ).start()
        _dispatch_loop = loop
        return loop


def _run_dispatch_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Body of the dispatch thread: own ``loop`` and serve it until process exit."""
    asyncio.set_event_loop(loop)
    loop.run_forever()


async def _deliver_event(method_name: str, coro: Coroutine[Any, Any, Any]) -> None:
    """Await one sink delivery under a deadline, never propagating a failure."""
    try:
        await asyncio.wait_for(coro, EVENT_DISPATCH_TIMEOUT_SECONDS)
    except TimeoutError:
        logger.warning(
            "AuthEventSink %s exceeded %ss and was dropped",
            method_name,
            EVENT_DISPATCH_TIMEOUT_SECONDS,
        )
    except Exception as err:
        _log_event_failure(method_name, err)


def wait_for_pending_events(timeout: float = 5.0) -> bool:
    """Block until every in-flight event delivery has finished.

    Dispatch is fire-and-forget, so a host that wants notifications flushed on
    shutdown — or a test that wants to assert on its sink — needs an explicit
    join point.

    Args:
        timeout: Maximum seconds to wait.

    Returns:
        ``True`` if the queue drained, ``False`` if ``timeout`` elapsed first.
    """
    with _dispatch_state:
        return _dispatch_state.wait_for(lambda: _inflight_events == 0, timeout)


def dispatch_event(method_name: str, event: object) -> None:
    """Best-effort, non-blocking emit of an :class:`AuthEventSink` notification.

    Security/notification events are fired from synchronous auth paths (login,
    lockout) through this helper. Delivery must never break — or slow down — the
    auth flow, so every failure is swallowed and logged, and a sink that does not
    implement ``method_name`` is skipped, letting a host sink written before an
    event existed keep working unchanged.

    The call always returns immediately: inside a running event loop the
    coroutine is scheduled as a background task, and from a sync worker thread it
    is handed to a shared dispatch loop instead of being run inline (which would
    pin a Starlette threadpool worker for the duration of the host's I/O). Each
    delivery is capped by :data:`EVENT_DISPATCH_TIMEOUT_SECONDS`, and events past
    :data:`MAX_INFLIGHT_EVENTS` are dropped rather than queued without bound.

    Args:
        method_name: The :class:`AuthEventSink` method to invoke.
        event: The event value passed to the handler.
    """
    handler = getattr(get_event_sink(), method_name, None)
    if handler is None:
        return
    try:
        coro = handler(event)
    except Exception as err:
        _log_event_failure(method_name, err)
        return
    if not _acquire_dispatch_slot(method_name):
        is_critical = method_name in CRITICAL_EVENT_METHODS
        logger.log(
            logging.ERROR if is_critical else logging.WARNING,
            "AuthEventSink %s dropped: %s deliveries already in flight%s",
            method_name,
            MAX_INFLIGHT_CRITICAL_EVENTS if is_critical else MAX_INFLIGHT_EVENTS,
            " (SECURITY-CRITICAL notification lost)" if is_critical else "",
        )
        with contextlib.suppress(Exception):
            coro.close()
        return
    delivery = _deliver_event(method_name, coro)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    try:
        if loop is not None:
            task = loop.create_task(delivery)
            task.add_done_callback(_release_dispatch_slot)
        else:
            future = asyncio.run_coroutine_threadsafe(delivery, _get_dispatch_loop())
            future.add_done_callback(_release_dispatch_slot)
    except Exception as err:
        _release_dispatch_slot()
        _log_event_failure(method_name, err)
        with contextlib.suppress(Exception):
            delivery.close()


async def adispatch_event(method_name: str, event: object) -> None:
    """Awaitable best-effort emit for async auth paths (e.g. token-theft).

    Same forward-compatible, never-raises contract as :func:`dispatch_event`, but
    awaited inline so a caller in an async endpoint delivers before returning.
    Still deadline-bounded, so a hung sink cannot hang the request.

    Args:
        method_name: The :class:`AuthEventSink` method to invoke.
        event: The event value passed to the handler.
    """
    handler = getattr(get_event_sink(), method_name, None)
    if handler is None:
        return
    try:
        coro = handler(event)
    except Exception as err:
        _log_event_failure(method_name, err)
        return
    await _deliver_event(method_name, coro)


def reset_ports() -> None:
    """Clear all installed adapters. Intended for test isolation."""
    _user_repository.reset()
    _settings_provider.reset()
    _event_sink.reset()
    _password_breach_checker.reset()
    _scope_resolver.reset()


__all__ = [
    "CRITICAL_EVENT_METHODS",
    "EVENT_DISPATCH_TIMEOUT_SECONDS",
    "MAX_INFLIGHT_CRITICAL_EVENTS",
    "MAX_INFLIGHT_EVENTS",
    "AccountLocked",
    "AuthEventSink",
    "AuthenticatorChanged",
    "EmailVerificationRequested",
    "IdpAccountLinked",
    "IdpIdentity",
    "NewDeviceLogin",
    "NullAuthEventSink",
    "NullPasswordBreachChecker",
    "PasswordBreachChecker",
    "PasswordPolicy",
    "PasswordResetRequested",
    "RefreshTokenTheftDetected",
    "ScopeResolver",
    "SettingsProvider",
    "SignupApproved",
    "SignupConfig",
    "SignupPendingAdminApproval",
    "TieredScopeResolver",
    "UserProtocol",
    "UserRepository",
    "adispatch_event",
    "configure_event_sink",
    "configure_password_breach_checker",
    "configure_scope_resolver",
    "configure_settings_provider",
    "configure_user_repository",
    "dispatch_event",
    "get_event_sink",
    "get_password_breach_checker",
    "get_scope_resolver",
    "get_settings_provider",
    "get_user_repository",
    "is_settings_provider_configured",
    "is_user_repository_configured",
    "reset_ports",
    "wait_for_pending_events",
]
