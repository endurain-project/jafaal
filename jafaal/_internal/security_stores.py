"""Authentication security stores for login and MFA lockout.

Pending-login bookkeeping and progressive lockout counters are kept in the
configured :class:`~jafaal.state_store.StateStore` (an in-process dict by
default, a distributed backend when the host configures one). The atomic
increment-and-lock step is delegated to
:meth:`~jafaal.state_store.StateStore.record_tiered_failure`, so this module
contains no backend-specific code or memory-vs-Redis split.
"""

import json
import logging
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn, Protocol, runtime_checkable
from urllib.parse import unquote

import jafaal.audit as jafaal_audit
import jafaal.ports as jafaal_ports
import jafaal.settings as jafaal_settings
from jafaal._core import hashing
from jafaal.exceptions import StoreUnavailableError
from jafaal.orm import UserId, coerce_user_id
from jafaal.state_store import (
    StateStore,
    StateStoreUnavailableError,
    get_state_store,
    raise_store_unavailable,
)

logger = logging.getLogger(__name__)


def _key_prefix() -> str:
    """Return the security-store key namespace prefix."""
    return jafaal_settings.get_settings().store_key_prefix


class AuthSecurityStoreUnavailableError(StoreUnavailableError):
    """
    Raised when auth security storage cannot be reached.

    Attributes:
        None.
    """


def _raise_store_unavailable(operation: str, err: StateStoreUnavailableError) -> NoReturn:
    """
    Log a storage outage and re-raise it as an auth-security-store error.

    Args:
        operation: Storage operation that failed.
        err: The provider outage error.

    Raises:
        AuthSecurityStoreUnavailableError: Always raised.
    """
    raise_store_unavailable(
        err,
        error_cls=AuthSecurityStoreUnavailableError,
        label="Auth security storage failed",
        message="auth security storage is unavailable",
        operation=operation,
        logger=logger,
    )


def normalize_username_key(username: str) -> str:
    """Normalise a username for security-store keys.

    Lockout counters must key on the same canonical form regardless of
    casing, surrounding whitespace, or URL-encoded variants supplied by
    the client.

    Args:
        username: Raw username string from the request.

    Returns:
        Canonical key suitable for lockout stores.

    Raises:
        None.
    """
    return unquote(username).replace("+", " ").strip().casefold()


def _username_digest(username: str) -> str:
    """
    Hash a normalized username for storage key names.

    Args:
        username: Username to normalize and hash.

    Returns:
        SHA-256 digest for use in storage keys.

    Raises:
        None.
    """
    return hashing.sha256_hex(normalize_username_key(username))


def username_log_identifier(username: str) -> str:
    """
    Build a non-reversible username identifier for logs.

    Args:
        username: Username to normalize and hash.

    Returns:
        Log-safe username identifier.

    Raises:
        None.
    """
    return f"username_hash={_username_digest(username)}"


def _now_epoch() -> int:
    """Get the current UTC epoch timestamp in seconds."""
    return int(datetime.now(UTC).timestamp())


@dataclass(frozen=True)
class PendingLogin:
    """A password-verified login awaiting its second factor.

    Attributes:
        user_id: The user who completed the password step.
        username: The username as supplied at login, used for the MFA lockout
            key and for audit records.
        client_id: The registered client the login was started for. The second
            factor must be completed against the same client: the client's
            registration decides token delivery (cookie vs body) and the scope
            ceiling, so letting the ticket be redeemed by a different one would
            let a login begun for a narrow, body-delivery client finish as a
            wide, cookie-delivery one.
        scope: The ``scope`` requested on the password step (RFC 6749 §3.3),
            re-applied when the second factor completes the login. Carried here
            rather than re-read from the second-factor request for the same
            reason as ``client_id``: a value the caller re-supplies at step two
            is a value it can widen at step two. Empty means "whatever this
            client and user are entitled to".
    """

    user_id: UserId
    username: str
    client_id: str
    scope: tuple[str, ...] = ()


def _datetime_from_epoch(epoch_seconds: int) -> datetime:
    """Convert an epoch timestamp to a timezone-aware UTC datetime."""
    return datetime.fromtimestamp(epoch_seconds, tz=UTC)


def _log_lockout(
    display_name: str,
    duration_label: str,
    subject: str,
    value: str,
    failed_count: int,
) -> None:
    """
    Log and audit a progressive lockout event.

    Args:
        display_name: Human-readable store name (e.g. ``"Login"``).
        duration_label: Human-readable lockout duration.
        subject: The kind of key being locked (``"username"`` or ``"ip"``); the
            audit record carries ``<subject>`` (the value) and ``<subject>_hash``
            (a non-reversible digest that survives PII scrubbing).
        value: The already-normalized subject value being locked out.
        failed_count: Failed attempt count that caused the lockout.

    Returns:
        None.
    """
    digest = hashing.sha256_hex(value)
    logger.warning(
        f"{display_name} lockout ({duration_label}) applied to {subject}_hash={digest} "
        f"after {failed_count} failed attempts",
        extra={f"{subject}_hash": digest, "failed_attempts": failed_count},
    )
    jafaal_audit.record(
        jafaal_audit.Event.LOCKOUT_APPLIED,
        outcome=jafaal_audit.Outcome.BLOCKED,
        level=logging.WARNING,
        store=display_name,
        failed_attempts=failed_count,
        lockout=duration_label,
        **{subject: value, f"{subject}_hash": digest},
    )
    # Best-effort host notification (e.g. "your account was locked"). Skipped for
    # sinks that do not implement it; never breaks the auth flow.
    jafaal_ports.dispatch_event(
        "on_account_locked",
        jafaal_ports.AccountLocked(
            subject=value,
            subject_kind=subject,
            store=display_name,
            failed_attempts=failed_count,
            lockout_label=duration_label,
        ),
    )


@runtime_checkable
class FailedLoginStore(Protocol):
    """Contract for failed-login lockout stores (per-username + per-source-IP)."""

    def is_locked_out(self, username: str) -> bool: ...

    def get_lockout_time(self, username: str) -> datetime | None: ...

    def record_failed_attempt(self, username: str) -> int: ...

    def reset_attempts(self, username: str) -> None: ...

    def is_ip_locked_out(self, ip: str) -> bool: ...

    def get_ip_lockout_time(self, ip: str) -> datetime | None: ...

    def record_ip_failure(self, ip: str) -> int: ...

    def reset_ip_attempts(self, ip: str) -> None: ...

    def clear_all(self) -> None: ...


@runtime_checkable
class PendingMFAStore(Protocol):
    """Contract for pending-MFA login stores (bookkeeping + MFA lockout).

    Pending logins are addressed by the opaque ``mfa_token`` minted when the
    password step succeeds — never by username. The lockout half of the contract
    is still keyed by username, because that is the subject being protected from
    brute force.
    """

    def add_pending_login(
        self,
        username: str,
        user_id: UserId,
        client_id: str,
        scope: Sequence[str] = (),
    ) -> str: ...

    def get_pending_login(self, mfa_token: str) -> PendingLogin | None: ...

    def claim_pending_login(self, mfa_token: str) -> PendingLogin | None: ...

    def delete_pending_login(self, mfa_token: str) -> None: ...

    def has_pending_login(self, mfa_token: str) -> bool: ...

    def clear_for_user(self, user_id: UserId) -> int: ...

    def cleanup_expired(self) -> int: ...

    def is_locked_out(self, username: str) -> bool: ...

    def get_lockout_time(self, username: str) -> datetime | None: ...

    def record_failed_attempt(self, username: str) -> int: ...

    def reset_attempts(self, username: str) -> None: ...

    def clear_all(self) -> None: ...


@runtime_checkable
class StepUpStore(Protocol):
    """Contract for step-up lockout stores. Keys are stable user identifiers."""

    def is_locked_out(self, key: str) -> bool: ...

    def get_lockout_time(self, key: str) -> datetime | None: ...

    def record_failed_attempt(self, key: str) -> int: ...

    def reset_attempts(self, key: str) -> None: ...

    def clear_all(self) -> None: ...


# Progressive-lockout thresholds. Each entry is ``(failed_count_threshold,
# lockout_seconds, duration_label)`` in ascending order; the highest matched
# threshold wins.
_LOGIN_LOCKOUT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (5, 5 * 60, "5 min"),
    (10, 30 * 60, "30 min"),
    (20, 24 * 60 * 60, "24 hours"),
)
# Per-source-IP thresholds. Higher than the per-username tiers because they
# aggregate failures across *all* usernames tried from one IP: they bound how
# many accounts a single IP can lock out (each account needs 5 failures, so ~10
# accounts trips the first IP tier) without penalising a busy shared egress that
# also has successful logins (which reset the counter).
_LOGIN_IP_LOCKOUT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (50, 15 * 60, "15 min"),
    (100, 60 * 60, "1 hour"),
    (250, 24 * 60 * 60, "24 hours"),
)
_MFA_LOCKOUT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (5, 5 * 60, "5 min"),
    (10, 30 * 60, "30 min"),
    (15, 2 * 60 * 60, "2 hours"),
)
_STEP_UP_LOCKOUT_THRESHOLDS: tuple[tuple[int, int, str], ...] = (
    (5, 5 * 60, "5 min"),
    (10, 30 * 60, "30 min"),
    (15, 2 * 60 * 60, "2 hours"),
)


class _ProgressiveLockout:
    """
    Progressive-lockout counter delegated to ``StateStore.record_tiered_failure``.

    Shared by all three security stores; the memory-vs-Redis atomicity lives in
    the provider, so this class only holds the thresholds and key layout.

    Attributes:
        _get_state: Callable returning the active state provider.
        _name: Logical store name used in key prefixes.
        _display_name: Human-readable name used in logs.
        _thresholds: ``(count, seconds, label)`` tuples, ascending.
        _attempts_ttl_seconds: TTL for failed-attempt counters.
        _normalize: Optional key-normaliser applied before hashing.
    """

    def __init__(
        self,
        get_state: "Callable[[], StateStore]",
        name: str,
        display_name: str,
        thresholds: tuple[tuple[int, int, str], ...],
        attempts_ttl_seconds: int,
        normalize_key: "Callable[[str], str] | None" = None,
        subject: str = "username",
    ) -> None:
        self._get_state = get_state
        self._name = name
        self._display_name = display_name
        self._thresholds = thresholds
        self._attempts_ttl_seconds = attempts_ttl_seconds
        self._normalize = normalize_key or (lambda key: key)
        self._subject = subject

    def _digest(self, key: str) -> str:
        return hashing.sha256_hex(self._normalize(key))

    def _counter_key(self, key: str) -> str:
        return f"{_key_prefix()}:{self._name}:attempts:{self._digest(key)}"

    def _gate_key(self, key: str) -> str:
        return f"{_key_prefix()}:{self._name}:lockout:{self._digest(key)}"

    def _duration_label(self, failed_count: int) -> str:
        for threshold, _lockout_seconds, label in reversed(self._thresholds):
            if failed_count >= threshold:
                return label
        return "unknown"

    def is_locked_out(self, key: str) -> bool:
        return self.get_lockout_time(key) is not None

    def get_lockout_time(self, key: str) -> datetime | None:
        gate_key = self._gate_key(key)
        try:
            raw_gate = self._get_state().get(gate_key)
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("get lockout time", err)
        if raw_gate is None:
            return None
        try:
            gate_until = int(raw_gate.decode())
        except (TypeError, ValueError):
            self._delete(gate_key, "delete invalid lockout")
            return None
        if gate_until <= _now_epoch():
            self._delete(gate_key, "delete expired lockout")
            return None
        return _datetime_from_epoch(gate_until)

    def record_failed_attempt(self, key: str) -> int:
        tiers = tuple((count, seconds) for count, seconds, _label in self._thresholds)
        try:
            outcome = self._get_state().record_tiered_failure(
                self._counter_key(key),
                self._gate_key(key),
                tiers,
                self._attempts_ttl_seconds,
            )
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("record failed attempt", err)
        if outcome.newly_locked:
            _log_lockout(
                self._display_name,
                self._duration_label(outcome.count),
                self._subject,
                self._normalize(key),
                outcome.count,
            )
        return outcome.count

    def reset_attempts(self, key: str) -> None:
        state = self._get_state()
        try:
            state.delete(self._counter_key(key))
            state.delete(self._gate_key(key))
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("reset attempts", err)

    def clear_all(self) -> None:
        try:
            self._get_state().delete_prefix(f"{_key_prefix()}:{self._name}:")
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("clear lockout store", err)

    def _delete(self, key: str, operation: str) -> None:
        try:
            self._get_state().delete(key)
        except StateStoreUnavailableError as err:
            _raise_store_unavailable(operation, err)


class FailedLoginAttempts:
    """
    Track failed login attempts with progressive lockout.

    Two independent dimensions guard the login endpoint:

    * **Per-username** (5/10/20 → 5m/30m/24h) bounds brute-force against a single
      account. Because it keys on the username, anyone who knows a username can
      trip it — i.e. it is also a *targeted-lockout* (DoS) lever: an attacker can
      lock a known account out by submitting bad passwords for it. This is
      inherent to per-account lockout.
    * **Per-source-IP** (50/100/250 → 15m/1h/24h) bounds how many accounts a
      single IP can lock out by *spraying* failures across many usernames, so the
      targeted-lockout lever above is not cheap at scale — an attacker must
      rotate IPs. It is reset on any successful login from the IP (so a busy
      shared egress rarely trips it) and gated by
      :attr:`~jafaal.settings.AuthSettings.login_ip_lockout_enabled`. It relies on
      an accurate client IP, so configure ``trusted_proxies`` behind a reverse
      proxy (otherwise every client shares the proxy's address).

    Attributes:
        _state_override: Explicit provider (tests); ``None`` resolves the
            process-wide provider lazily at call time.
        _lockout: Per-username progressive-lockout helper.
        _ip_lockout: Per-source-IP progressive-lockout helper.
    """

    def __init__(self, state: StateStore | None = None) -> None:
        self._state_override = state
        self._lockout = _ProgressiveLockout(
            self._get_state,
            name="login",
            display_name="Login",
            thresholds=_LOGIN_LOCKOUT_THRESHOLDS,
            attempts_ttl_seconds=24 * 60 * 60,
            normalize_key=normalize_username_key,
        )
        self._ip_lockout = _ProgressiveLockout(
            self._get_state,
            name="login_ip",
            display_name="Login (per-IP)",
            thresholds=_LOGIN_IP_LOCKOUT_THRESHOLDS,
            attempts_ttl_seconds=60 * 60,
            subject="ip",
        )

    def _get_state(self) -> StateStore:
        return self._state_override if self._state_override is not None else get_state_store()

    def _ip_lockout_enabled(self) -> bool:
        return jafaal_settings.get_settings().login_ip_lockout_enabled

    # --- per-username lockout ---
    def is_locked_out(self, username: str) -> bool:
        """Check if a username is locked out from failed logins."""
        return self._lockout.is_locked_out(username)

    def get_lockout_time(self, username: str) -> datetime | None:
        """Get the lockout expiry for a username, if locked out."""
        return self._lockout.get_lockout_time(username)

    def record_failed_attempt(self, username: str) -> int:
        """Record a failed login and return the current attempt count."""
        return self._lockout.record_failed_attempt(username)

    def reset_attempts(self, username: str) -> None:
        """Clear the failed-attempt counter on successful login."""
        self._lockout.reset_attempts(username)

    # --- per-source-IP backoff ---
    def is_ip_locked_out(self, ip: str) -> bool:
        """Check if a source IP is under the per-IP failed-login backoff."""
        if not self._ip_lockout_enabled():
            return False
        return self._ip_lockout.is_locked_out(ip)

    def get_ip_lockout_time(self, ip: str) -> datetime | None:
        """Get the per-IP backoff expiry for a source IP, if active."""
        if not self._ip_lockout_enabled():
            return None
        return self._ip_lockout.get_lockout_time(ip)

    def record_ip_failure(self, ip: str) -> int:
        """Record a failed login against the source IP; return the count (0 if disabled)."""
        if not self._ip_lockout_enabled():
            return 0
        return self._ip_lockout.record_failed_attempt(ip)

    def reset_ip_attempts(self, ip: str) -> None:
        """Deliberately a no-op — see below.

        The per-username counter is reset on a successful login because
        authenticating *as that user* proves the failures were that user
        fumbling their own password. No equivalent proof exists per IP: an
        address is shared by many accounts, so a success from it says nothing
        about the failures against other usernames.

        Resetting it made the per-IP tier — the only bound on the targeted
        lockout DoS the username tier enables — trivially defeatable: spray 49
        failures at victims, log in once to an account you own, repeat, and lock
        out arbitrarily many accounts from one address. The counter instead
        decays on its own ``attempts_ttl_seconds`` window, which is what keeps a
        legitimate NAT gateway from accumulating failures forever.

        Kept as a method (rather than removed) so the call site still reads as
        "success handling", with the reasoning attached to the behaviour.
        """
        return

    def clear_all(self) -> None:
        """Clear all failed-login records (per-username and per-IP)."""
        self._lockout.clear_all()
        self._ip_lockout.clear_all()


class PendingMFALogin:
    """
    Manage pending MFA logins plus per-username MFA failure lockout (5/10/15).

    A pending login is addressed by an **opaque, single-use ``mfa_token``**
    minted when the password step succeeds and returned to that caller only. The
    username is *not* an address: it is public (or guessable), so keying the
    pending record on it would mean anyone holding a valid one-time code could
    complete a login during the window a legitimate password step opened —
    collapsing two factors back to one. Possession of the ticket is the proof
    that the password factor was satisfied *by this caller*.

    The ticket survives failed code attempts (a user may mistype) and is
    consumed atomically by :meth:`claim_pending_login` on success; the MFA
    lockout tiers bound how many attempts it can absorb.

    Attributes:
        PENDING_MFA_TTL_SECONDS: TTL for pending MFA entries.
        _state_override: Explicit provider (tests); ``None`` resolves lazily.
        _lockout: Shared progressive-lockout helper for MFA failures.
    """

    PENDING_MFA_TTL_SECONDS: int = 300

    def __init__(self, state: StateStore | None = None) -> None:
        self._state_override = state
        self._lockout = _ProgressiveLockout(
            self._get_state,
            name="mfa",
            display_name="MFA",
            thresholds=_MFA_LOCKOUT_THRESHOLDS,
            attempts_ttl_seconds=2 * 60 * 60,
            normalize_key=normalize_username_key,
        )

    def _get_state(self) -> StateStore:
        return self._state_override if self._state_override is not None else get_state_store()

    def _pending_key(self, mfa_token: str) -> str:
        # The stored key is a digest of the ticket, so the state store never
        # holds anything that could be replayed as the ticket itself.
        return f"{_key_prefix()}:mfa:pending:{hashing.sha256_hex(mfa_token)}"

    @staticmethod
    def _encode(user_id: UserId, username: str, client_id: str, scope: Sequence[str]) -> bytes:
        """Serialise a pending login for storage."""
        return json.dumps({"uid": str(user_id), "un": username, "cid": client_id, "sc": list(scope)}).encode()

    @staticmethod
    def _decode(raw: bytes) -> PendingLogin | None:
        """Parse a stored pending login, or ``None`` if it is unusable."""
        try:
            payload = json.loads(raw.decode())
            # The id is stored in its string form and coerced back to the host
            # user table's primary-key type (``int`` or ``uuid.UUID``) on read,
            # so the store works for both integer- and UUID-keyed hosts.
            # ``sc`` is read defensively: an entry written by an older release
            # predates it, and an in-flight login must not be invalidated by a
            # deploy.
            return PendingLogin(
                coerce_user_id(payload["uid"]),
                payload["un"],
                payload["cid"],
                tuple(payload.get("sc") or ()),
            )
        except (TypeError, ValueError, KeyError, AttributeError):
            return None

    def add_pending_login(
        self,
        username: str,
        user_id: UserId,
        client_id: str,
        scope: Sequence[str] = (),
    ) -> str:
        """Record a pending MFA login and return its opaque ticket.

        Args:
            username: The username that just passed the password step.
            user_id: The user the pending login belongs to.
            client_id: The registered client the login was started for; the
                second factor must be completed against the same one.
            scope: The ``scope`` requested on the password step, re-applied when
                the second factor completes the login.

        Returns:
            The ``mfa_token`` to hand to the caller; it must be presented to
            complete the second factor.
        """
        mfa_token = secrets.token_urlsafe(32)
        try:
            self._get_state().set(
                self._pending_key(mfa_token),
                self._encode(user_id, username, client_id, scope),
                ttl_seconds=self.PENDING_MFA_TTL_SECONDS,
            )
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("add pending MFA login", err)
        return mfa_token

    def get_pending_login(self, mfa_token: str) -> PendingLogin | None:
        """Resolve a pending MFA login from its ticket, evicting corrupt entries."""
        pending_key = self._pending_key(mfa_token)
        try:
            raw = self._get_state().get(pending_key)
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("get pending MFA login", err)
        if raw is None:
            return None
        pending = self._decode(raw)
        if pending is None:
            try:
                self._get_state().delete(pending_key)
            except StateStoreUnavailableError as err:
                _raise_store_unavailable("delete invalid pending MFA login", err)
        return pending

    def claim_pending_login(self, mfa_token: str) -> PendingLogin | None:
        """Atomically consume a pending MFA login, so one ticket logs in once."""
        try:
            raw = self._get_state().get_and_delete(self._pending_key(mfa_token))
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("claim pending MFA login", err)
        if raw is None:
            return None
        return self._decode(raw)

    def delete_pending_login(self, mfa_token: str) -> None:
        """Remove the pending MFA login addressed by ``mfa_token``."""
        try:
            self._get_state().delete(self._pending_key(mfa_token))
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("delete pending MFA login", err)

    def clear_for_user(self, user_id: UserId) -> int:
        """Remove every pending MFA login entry tied to a user ID."""
        target = str(user_id)
        removed = 0
        state = self._get_state()
        try:
            for pending_key in list(state.iter_keys(f"{_key_prefix()}:mfa:pending:")):
                raw = state.get(pending_key)
                if raw is None:
                    continue
                pending = self._decode(raw)
                if pending is not None and str(pending.user_id) == target:
                    state.delete(pending_key)
                    removed += 1
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("clear pending MFA logins for user", err)
        return removed

    def has_pending_login(self, mfa_token: str) -> bool:
        """Check whether ``mfa_token`` addresses a valid pending MFA login."""
        return self.get_pending_login(mfa_token) is not None

    def cleanup_expired(self) -> int:
        """Return zero because the backend expires pending entries by TTL."""
        return 0

    def is_locked_out(self, username: str) -> bool:
        """Check if a username is locked out from MFA attempts."""
        return self._lockout.is_locked_out(username)

    def get_lockout_time(self, username: str) -> datetime | None:
        """Get the MFA lockout expiry for a username, if locked out."""
        return self._lockout.get_lockout_time(username)

    def record_failed_attempt(self, username: str) -> int:
        """Record a failed MFA attempt and return the current count."""
        return self._lockout.record_failed_attempt(username)

    def reset_attempts(self, username: str) -> None:
        """Reset the MFA failure counter after a successful verification."""
        self._lockout.reset_attempts(username)

    def clear_all(self) -> None:
        """Clear all pending logins and MFA failure records."""
        try:
            self._get_state().delete_prefix(f"{_key_prefix()}:mfa:pending:")
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("clear pending MFA logins", err)
        self._lockout.clear_all()


class StepUpAttempts:
    """
    Track failed step-up verification attempts (5/10/15 → 5m/30m/2h).

    Keys are stable user identifiers (e.g. ``user:{user_id}``).

    Attributes:
        _state_override: Explicit provider (tests); ``None`` resolves lazily.
        _lockout: Shared progressive-lockout helper.
    """

    def __init__(self, state: StateStore | None = None) -> None:
        self._state_override = state
        self._lockout = _ProgressiveLockout(
            self._get_state,
            name="step_up",
            display_name="Step-up",
            thresholds=_STEP_UP_LOCKOUT_THRESHOLDS,
            attempts_ttl_seconds=2 * 60 * 60,
        )

    def _get_state(self) -> StateStore:
        return self._state_override if self._state_override is not None else get_state_store()

    def is_locked_out(self, key: str) -> bool:
        """Check if a user key is locked out from step-up."""
        return self._lockout.is_locked_out(key)

    def get_lockout_time(self, key: str) -> datetime | None:
        """Get the step-up lockout expiry for a user key, if locked out."""
        return self._lockout.get_lockout_time(key)

    def record_failed_attempt(self, key: str) -> int:
        """Record a failed step-up attempt and return the current count."""
        return self._lockout.record_failed_attempt(key)

    def reset_attempts(self, key: str) -> None:
        """Reset the step-up failure counter for a user key."""
        self._lockout.reset_attempts(key)

    def clear_all(self) -> None:
        """Clear all step-up failure records."""
        self._lockout.clear_all()


failed_login_attempts: FailedLoginStore = FailedLoginAttempts()
pending_mfa_store: PendingMFAStore = PendingMFALogin()
step_up_attempts: StepUpStore = StepUpAttempts()


def get_failed_login_attempts() -> FailedLoginStore:
    """Dependency injection for failed-login attempt storage."""
    return failed_login_attempts


def get_pending_mfa_store() -> PendingMFAStore:
    """Dependency injection for pending MFA storage."""
    return pending_mfa_store


def get_step_up_attempts() -> StepUpStore:
    """Dependency injection for step-up attempt tracking."""
    return step_up_attempts


def cleanup_expired_pending_mfa_logins() -> int:
    """Evict all expired pending MFA login entries (no-op; TTL-managed).

    Returns the number of entries evicted (always ``0`` — the backend expires
    pending entries by TTL).
    """
    return pending_mfa_store.cleanup_expired()


def clear_pending_mfa_for_user(user_id: UserId) -> int:
    """
    Remove pending MFA login entries for a user across credential changes.

    Called from password-change paths so that an attacker who already submitted
    the now-rotated password and is sitting at the pending-MFA step cannot still
    complete the login. Storage outages are logged and swallowed because the
    password rotation itself must remain successful; pending entries expire
    naturally after their 5-minute TTL.

    Args:
        user_id: User ID whose pending MFA entries should be removed.

    Returns:
        Number of pending MFA entries removed (zero on storage outage).
    """
    try:
        return pending_mfa_store.clear_for_user(user_id)
    except AuthSecurityStoreUnavailableError as err:
        logger.warning(
            "Failed to clear pending MFA entries during password change; entries will expire naturally via TTL",
            exc_info=err,
        )
        return 0


# ---------------------------------------------------------------------------
# Step-up re-authentication grants
#
# A fresh IdP re-authentication (OIDC prompt=login with a verified, recent
# auth_time) mints a short-lived, single-use grant here. It lets an SSO-only
# account (no local password, no MFA) satisfy step-up without local MFA — the
# second factor is delegated to the identity provider. The grant lives in the
# ephemeral StateStore (TTL-expiring, distributed when Redis is configured) and
# is consumed atomically on use.
# ---------------------------------------------------------------------------


def _step_up_grant_key(user_id: UserId) -> str:
    """Return the state-store key holding a user's step-up re-auth grant."""
    return f"{_key_prefix()}:stepup:grant:{hashing.sha256_hex(str(user_id))}"


def grant_step_up_reauth(user_id: UserId, *, idp_id: int, ttl_seconds: int) -> None:
    """Record a single-use step-up grant from a fresh IdP re-authentication.

    Called by the SSO callback after it has verified the re-authenticated
    identity matches the user's linked account and that the provider asserted a
    recent ``auth_time``. The stored value is the originating ``idp_id`` (audit
    only); presence of the key is what authorises the next step-up.

    Args:
        user_id: The re-authenticated user.
        idp_id: The identity provider the user re-authenticated against.
        ttl_seconds: Grant lifetime; the caller must retry within this window.

    Raises:
        AuthSecurityStoreUnavailableError: 503 if the state store is unreachable.
    """
    try:
        get_state_store().set(_step_up_grant_key(user_id), str(idp_id).encode(), ttl_seconds=ttl_seconds)
    except StateStoreUnavailableError as err:
        _raise_store_unavailable("grant step-up reauth", err)


def consume_step_up_reauth_grant(user_id: UserId) -> bool:
    """Atomically consume a user's step-up re-auth grant, if present.

    Single-use: one fresh IdP re-authentication authorises exactly one
    subsequent sensitive operation. A state-store outage is treated as "no
    grant" so step-up falls through to another factor (fail closed) rather than
    granting access on unverifiable state.

    Args:
        user_id: The user attempting a step-up-protected operation.

    Returns:
        True if a valid grant existed and was consumed, False otherwise.
    """
    try:
        return get_state_store().get_and_delete(_step_up_grant_key(user_id)) is not None
    except StateStoreUnavailableError as err:
        logger.warning("Step-up grant check skipped; state store unavailable", exc_info=err)
        return False


def clear_step_up_reauth_grant(user_id: UserId) -> None:
    """Drop an unconsumed step-up grant for ``user_id``.

    Part of the credential-change sweep. A grant is a bearer licence to perform
    one sensitive operation — change a password, mint an API key, bind or remove
    a passkey — without presenting any factor at all. Leaving one live across a
    password reset means the reset does not actually evict whoever obtained it.

    Best-effort, like every other entry in the sweep: the credential change must
    succeed regardless, and the grant's TTL is short.

    Args:
        user_id: The user whose outstanding grant is dropped.
    """
    try:
        get_state_store().delete(_step_up_grant_key(user_id))
    except StateStoreUnavailableError as err:
        logger.warning("Could not drop the step-up grant; it will expire via TTL", exc_info=err)
