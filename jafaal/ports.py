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

Value types that cross the boundary (:class:`SignupData`, :class:`IdpIdentity`
and the event dataclasses) are plain frozen dataclasses — framework-agnostic,
like :class:`jafaal.principal.Principal`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


# ===========================================================================
# User boundary
# ===========================================================================


@runtime_checkable
class UserProtocol(Protocol):
    """The user attributes JAFAAL reads across the boundary.

    Satisfied by a host user model built on :class:`jafaal.UserMixin` (Phase 3):
    ``id``, ``username``, ``email``, ``is_active``, ``is_superuser``,
    ``is_verified``, and the ``mfa_enabled`` property. JAFAAL never reads
    app-specific profile fields.
    """

    id: Any
    username: str
    email: str
    is_active: bool
    is_superuser: bool
    is_verified: bool

    @property
    def mfa_enabled(self) -> bool: ...


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
        """
        ...

    def provision_from_idp(self, identity: IdpIdentity, db: Session) -> UserProtocol:
        """Create a user row from an IdP identity and return it.

        The account has no local password (JAFAAL persists no credential).
        Profile shape and defaults are the host's concern.
        """
        ...

    def sync_from_idp(self, user_id: Any, claims: Mapping[str, Any], db: Session) -> None:
        """Optionally sync host-owned profile fields from refreshed IdP claims.

        ``claims`` is the mapped IdP claim dict (e.g. ``email``, ``name``). Called
        on subsequent logins when IdP→user sync is enabled; the host decides which
        fields to update and resolves any email conflicts.
        """
        ...

    def set_email_verified(self, user_id: Any, db: Session, *, activate: bool) -> None:
        """Mark the user's email address as verified.

        When ``activate`` is ``True`` the account is also activated (used when
        email verification is the last gate before login); when ``False`` the
        account stays inactive (e.g. admin approval is still pending).
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


# ===========================================================================
# Installed-adapter accessors (mirror jafaal.settings.configure/get_settings)
# ===========================================================================

_user_repository: UserRepository | None = None
_settings_provider: SettingsProvider | None = None
_event_sink: AuthEventSink = NullAuthEventSink()


def configure_user_repository(repository: UserRepository) -> None:
    """Install the host's :class:`UserRepository`. Call once at startup."""
    global _user_repository
    _user_repository = repository


def get_user_repository() -> UserRepository:
    """Return the installed :class:`UserRepository`.

    Raises:
        RuntimeError: If none has been configured.
    """
    if _user_repository is None:
        raise RuntimeError(
            "JAFAAL has no UserRepository configured. Call "
            "jafaal.configure_user_repository(...) at application startup."
        )
    return _user_repository


def configure_settings_provider(provider: SettingsProvider) -> None:
    """Install the host's :class:`SettingsProvider`. Call once at startup."""
    global _settings_provider
    _settings_provider = provider


def get_settings_provider() -> SettingsProvider:
    """Return the installed :class:`SettingsProvider`.

    Raises:
        RuntimeError: If none has been configured.
    """
    if _settings_provider is None:
        raise RuntimeError(
            "JAFAAL has no SettingsProvider configured. Call "
            "jafaal.configure_settings_provider(...) at application startup."
        )
    return _settings_provider


def configure_event_sink(sink: AuthEventSink) -> None:
    """Install the host's :class:`AuthEventSink` (defaults to a no-op sink)."""
    global _event_sink
    _event_sink = sink


def get_event_sink() -> AuthEventSink:
    """Return the installed :class:`AuthEventSink` (``NullAuthEventSink`` by default)."""
    return _event_sink


def reset_ports() -> None:
    """Clear all installed adapters. Intended for test isolation."""
    global _user_repository, _settings_provider, _event_sink
    _user_repository = None
    _settings_provider = None
    _event_sink = NullAuthEventSink()


__all__ = [
    "AuthEventSink",
    "EmailVerificationRequested",
    "IdpIdentity",
    "NullAuthEventSink",
    "PasswordPolicy",
    "PasswordResetRequested",
    "SettingsProvider",
    "SignupApproved",
    "SignupConfig",
    "SignupPendingAdminApproval",
    "UserProtocol",
    "UserRepository",
    "configure_event_sink",
    "configure_settings_provider",
    "configure_user_repository",
    "get_event_sink",
    "get_settings_provider",
    "get_user_repository",
    "reset_ports",
]
