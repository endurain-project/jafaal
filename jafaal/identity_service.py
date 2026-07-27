"""The two auth boundary protocols, and the implementation of both.

JAFAAL exposes two protocols because a host has two genuinely separate reasons to
replace something here:

* :class:`IdentityService` — *how do I recognise this caller, and how do I start
  and stop their session?* Swapped by an application that authenticates against
  LDAP, an upstream IdP, or a legacy session table.
* :class:`LocalCredentialStore` — *where do password hashes live, and how are
  they produced and checked?* Swapped by a deployment that keeps hashes in an
  external vault or must use a specific KDF.

Neither is a table of contents for the library. MFA enrolment, session listing,
password-change workflows, and identity-provider links are JAFAAL's own
application services and live in their own modules
(:mod:`jafaal._internal.services`, :mod:`jafaal.mfa`, :mod:`jafaal.sessions`) —
reached directly with a session, not through a bound facade. A boundary that
listed them would have forced a host to re-implement two dozen methods it never
wanted to change in order to swap the one it did.

Transaction contract
--------------------
Neither protocol owns transaction policy. Implementations delegate database work
to JAFAAL's CRUD helpers, which flush and leave the commit to the caller's unit
of work.

Request-state caching
---------------------
The resolved :class:`~jafaal.principal.Principal` should be stored on
``request.state.principal`` after the first resolution so that
multiple FastAPI dependencies in the same request do not trigger
duplicate database lookups.

Usage
-----
Inject via the ``get_identity_service`` FastAPI dependency, annotating the
parameter with whichever protocol the endpoint actually needs. A new
:class:`DefaultIdentityService` instance is returned per request;
never use a module-level singleton.
"""

from __future__ import annotations

import hmac
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Protocol, runtime_checkable

from fastapi import Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.token_denylist as jafaal_token_denylist
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.api_keys.crud as jafaal_api_keys_crud
import jafaal.api_keys.utils as jafaal_api_keys_utils
import jafaal.audit as jafaal_audit
import jafaal.credentials.crud as jafaal_credentials_crud
import jafaal.exceptions as jafaal_exceptions
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
import jafaal.utils as jafaal_utils
from jafaal._core import network, timeutils
from jafaal.orm import UserId
from jafaal.principal import (
    AccessTokenCred,
    ApiKeyCred,
    OAuthCred,
    PasswordCred,
    Principal,
    SessionCookieCred,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    pass

__all__ = [
    "DefaultIdentityService",
    "IdentityService",
    "LocalCredentialStore",
    "get_identity_service",
]


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class IdentityService(Protocol):
    """The credential boundary: turn a credential into a :class:`Principal`.

    Seven methods, and they are seven because that is what a host could
    plausibly re-implement: *how do I recognise this caller, and how do I start
    and stop their session?* An application that authenticates against LDAP,
    an upstream IdP, or a legacy session table swaps this and keeps the rest of
    JAFAAL.

    It deliberately does **not** cover MFA enrolment, session listing, password
    changes, or identity-provider links. Those are JAFAAL's own application
    services, reached through their own modules; putting them here would have
    made the "boundary" a table of contents for the library, and a host would
    have had to re-implement two dozen methods it never wanted to change in
    order to swap the one it did. Local password storage is its own seam — see
    :class:`LocalCredentialStore`.

    Every method may raise :class:`~jafaal.exceptions.JafaalError` on invalid or
    expired credentials, except :meth:`check_scope`, which raises only on a
    missing scope.

    Implementations own no transaction policy: they delegate database work to
    JAFAAL's CRUD helpers, which flush and leave the commit to the caller's unit
    of work.
    """

    def authenticate_password(
        self,
        username: str,
        password: str,
    ) -> Principal:
        """Verify username/password and return a Principal.

        Args:
            username: The username supplied by the caller.
            password: The plaintext password to verify.

        Returns:
            Principal: Resolved principal with a
                :class:`~jafaal.principal.PasswordCred`.

        Raises:
            JafaalError: 401 if the credentials are
                invalid or the account does not exist.
        """
        ...

    def resolve_from_access_token(
        self,
        access_token: str,
    ) -> Principal:
        """Validate a JWT access token and return a Principal.

        Args:
            access_token: The raw JWT string from the
                Authorization header.

        Returns:
            Principal: Resolved principal with an
                :class:`~jafaal.principal.AccessTokenCred`.

        Raises:
            JafaalError: 401 if the token is expired,
                invalid, or the user is not found.
        """
        ...

    def resolve_from_api_key(
        self,
        raw_key: str,
        request: Request,
    ) -> Principal:
        """Validate a raw API key and return a Principal.

        Args:
            raw_key: The plain-text API key from the
                ``X-API-Key`` header or ``?api_key=``
                query parameter.
            request: The current HTTP request (used for
                audit logging).

        Returns:
            Principal: Resolved principal with an
                :class:`~jafaal.principal.ApiKeyCred`.

        Raises:
            JafaalError: 401 if the key is not found,
                revoked, or expired.
        """
        ...

    def resolve_from_session_cookie(
        self,
        session_id: str,
    ) -> Principal:
        """Validate a session ID and return a Principal.

        Args:
            session_id: The session identifier from the
                cookie or token ``sid`` claim.

        Returns:
            Principal: Resolved principal with a
                :class:`~jafaal.principal.SessionCookieCred`.

        Raises:
            JafaalError: 401 if the session is not
                found or has expired.
        """
        ...

    def issue_token_pair(
        self,
        user: jafaal_ports.UserProtocol,
        session_id: str | None = None,
    ) -> tuple[str, datetime, str, datetime, str, str]:
        """Issue an access/refresh token pair for a user.

        Args:
            user: The validated user object.
            session_id: Optional existing session
                identifier; a new UUID is generated
                when ``None``.

        Returns:
            tuple: ``(session_id, access_token_exp,
                access_token, refresh_token_exp,
                refresh_token, csrf_token)``.
        """
        ...

    def revoke_session(
        self,
        session_id: str,
        user_id: UserId,
    ) -> None:
        """Revoke and delete a session.

        Args:
            session_id: The session to revoke.
            user_id: Owner of the session (used to
                prevent cross-user revocations).

        Raises:
            JafaalError: 404 if the session is not
                found for this user.
        """
        ...

    def check_scope(
        self,
        principal: Principal,
        required_scopes: frozenset[str],
    ) -> None:
        """Assert that the principal holds all required scopes.

        Args:
            principal: The authenticated principal.
            required_scopes: Scope strings that must all
                be present in ``principal.scopes``.

        Raises:
            JafaalError: 403 if any required scope is
                missing.
        """
        ...


@runtime_checkable
class LocalCredentialStore(Protocol):
    """Where local passwords live, and how they are hashed and verified.

    A separate seam from :class:`IdentityService` because it answers a different
    question and is swapped for different reasons: a deployment that keeps
    password hashes in an external vault, or that must use a specific FIPS-
    validated KDF, replaces this and leaves credential resolution alone.

    The hash itself never leaves this boundary except through
    :meth:`get_password_hash`; every other consumer works with the derived
    :meth:`has_local_password` or asks this store to verify.

    :class:`DefaultIdentityService` implements both protocols, so the common
    case wires one object.
    """

    def validate_and_hash_password(
        self,
        password: str,
        min_length: int,
        password_type: str,
        max_length: int | None = None,
    ) -> str:
        """Validate password policy and return a secure hash.

        Args:
            password: Plaintext password to validate and hash.
            min_length: Minimum configured password length.
            password_type: Configured password policy type.
            max_length: Maximum accepted length, or ``None`` for no maximum.

        Returns:
            Secure password hash.

        Raises:
            JafaalError: 400 if the password policy fails.
        """
        ...

    def hash_password(self, password: str) -> str:
        """Return a secure hash for a trusted generated secret.

        Args:
            password: Plaintext password or generated secret.

        Returns:
            Secure hash.
        """
        ...

    def verify_password(
        self,
        password: str,
        password_hash: str,
    ) -> bool:
        """Verify a plaintext password against a stored hash.

        Args:
            password: Plaintext password supplied by the caller.
            password_hash: Stored password hash.

        Returns:
            True if the password matches, False otherwise.
        """
        ...

    def get_password_hash(self, user_id: UserId) -> str | None:
        """Return a user's stored local password hash, or ``None``.

        ``None`` means the account has no local password (for example an
        SSO-only account).

        Args:
            user_id: ID of the user to read the credential for.

        Returns:
            The stored password hash, or ``None`` if no credential exists.
        """
        ...

    def has_local_password(self, user_id: UserId) -> bool:
        """Return whether a user has a local password credential.

        ``False`` means the account is SSO-only (no row in
        ``users_local_credentials``). The password hash itself is never
        exposed; only this derived boolean is returned.

        Args:
            user_id: ID of the user to check the credential for.

        Returns:
            True if a local credential row exists, False otherwise.
        """
        ...

    def set_local_password_hash(self, user_id: UserId, password_hash: str) -> None:
        """Insert or update a user's local password hash.

        Args:
            user_id: ID of the user to write the credential for.
            password_hash: Argon2/bcrypt password hash to store.

        Returns:
            None.
        """
        ...

    def clear_local_password(self, user_id: UserId) -> None:
        """Remove a user's local password credential, if present.

        Args:
            user_id: ID of the user whose credential should be removed.

        Returns:
            None.
        """
        ...


class DefaultIdentityService:
    """The batteries-included implementation of both auth protocols.

    Satisfies :class:`IdentityService` (credential resolution, session
    lifecycle, scope checks) and :class:`LocalCredentialStore` (password storage
    and hashing). A host swapping one and keeping the other wires two objects; a
    host swapping neither wires this.

    Constructor injects all per-request dependencies explicitly so that
    each method is testable in isolation.

    Transaction contract: this service does not mutate ORM state
    directly. It delegates database work to auth CRUD helpers, which
    flush and leave the commit to the caller's unit of work.

    Attributes:
        _db: SQLAlchemy database session for this request.
        _token_manager: JWT token manager.
        _password_hasher: Password hasher/verifier.
    """

    def __init__(
        self,
        db: Session,
        token_manager: jafaal_token_manager.TokenManager,
        password_hasher: jafaal_password_hasher.PasswordHasher,
    ) -> None:
        """
        Initialise the service with per-request dependencies.

        Args:
            db: SQLAlchemy database session.
            token_manager: Configured JWT token manager.
            password_hasher: Argon2/bcrypt password hasher.
        """
        self._db = db
        self._token_manager = token_manager
        self._password_hasher = password_hasher

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_principal(
        self,
        user: jafaal_ports.UserProtocol,
        scopes: list[str],
        credential: (PasswordCred | AccessTokenCred | ApiKeyCred | SessionCookieCred | OAuthCred),
    ) -> Principal:
        """Build a ``Principal`` from an ORM user row.

        Args:
            user: The resolved user, satisfying :class:`~jafaal.ports.UserProtocol`.
            scopes: List of granted OAuth2 scope strings.
            credential: Typed credential variant.

        Returns:
            Principal: Frozen principal ready to cache on
                ``request.state``.
        """
        return Principal(
            user_id=user.id,
            username=user.username,
            email=user.email,
            is_active=bool(user.is_active),
            is_superuser=jafaal_ports.is_superuser(user),
            scopes=frozenset(scopes),
            credential=credential,
        )

    def _enforce_session_binding(self, session_id: str, user_id: UserId) -> None:
        """Reject an access token whose session is gone, expired, or not the caller's.

        Enabled by :attr:`~jafaal.settings.AuthSettings.strict_session_binding`.
        Access tokens are otherwise stateless, so logout / single-session
        revocation only takes effect once the short-lived token expires. Binding
        every access-token-authenticated request to a still-valid server-side
        session — the same lifecycle (existence, absolute expiry, and idle/
        absolute timeout) the refresh flow enforces — makes revocation immediate,
        at the cost of one indexed session lookup per request.

        Args:
            session_id: The ``sid`` claim from the access token.
            user_id: The ``sub`` claim, coerced to the user table's PK type.

        Raises:
            JafaalError: 401 ``session_expired`` if the session is missing,
                expired, or timed out; 401 ``invalid_token`` if the session
                belongs to a different user.
        """
        session = jafaal_sessions_crud.get_session_by_id_not_expired(session_id, self._db)
        if session is None:
            raise jafaal_exceptions.SessionExpiredError("Session has been revoked or has expired.")
        if session.user_id != user_id:
            logger.warning(
                f"Access-token session owner mismatch: token sub={user_id}, session user_id={session.user_id}"
            )
            raise jafaal_exceptions.InvalidTokenError("Invalid access token")
        jafaal_sessions_utils.validate_session_timeout(session)

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    def authenticate_password(
        self,
        username: str,
        password: str,
    ) -> Principal:
        """Verify username/password and return a Principal.

        Args:
            username: The username supplied by the caller.
            password: The plaintext password to verify.

        Returns:
            Principal: Resolved principal with a
                :class:`~jafaal.principal.PasswordCred`.

        Raises:
            JafaalError: 401 if the credentials are
                invalid or the account does not exist.
        """
        user = jafaal_utils.authenticate_user(
            username,
            password,
            self._password_hasher,
            self._db,
        )
        # Scopes are determined by the token-issuing step;
        # at password-auth time we return an empty set so
        # callers know authentication succeeded but must
        # call issue_token_pair to get scoped tokens.
        return self._build_principal(user, [], PasswordCred(username=username))

    def resolve_from_access_token(
        self,
        access_token: str,
    ) -> Principal:
        """Validate a JWT access token and return a Principal.

        Args:
            access_token: The raw JWT string from the
                Authorization header.

        Returns:
            Principal: Resolved principal with an
                :class:`~jafaal.principal.AccessTokenCred`.

        Raises:
            JafaalError: 401 if the token is expired,
                invalid, the user is not found, or (when
                ``AuthSettings.strict_session_binding`` is enabled) the
                token's session has been revoked or has expired.
        """
        self._token_manager.validate_access_expiration_logged(access_token)

        # Decode once and read every claim off the result. Calling
        # ``get_token_claim`` per claim would re-verify the signature each time
        # (four times per authenticated request).
        claims = self._token_manager.decode_token(access_token).claims

        sub = claims.get("sub")
        if not isinstance(sub, int | str) or sub == "":
            raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sub' claim is missing or malformed")
        try:
            user_id = jafaal_orm.coerce_user_id(sub)
        except (ValueError, TypeError) as err:
            raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sub' claim is malformed") from err

        # ``scope`` is the RFC 6749 §3.3 space-delimited string.
        scope = jafaal_token_manager.scopes_from_claims(claims)
        if scope is None:
            raise jafaal_exceptions.InvalidTokenError("Invalid token: 'scope' claim must be a space-delimited string")

        sid = claims.get("sid")
        if not isinstance(sid, str):
            raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sid' claim must be a string")

        user = jafaal_user_guards.get_user_by_id_or_404(user_id, self._db)
        jafaal_user_guards.check_user_is_active(user)

        settings = jafaal_settings.get_settings()
        # Reject a token whose jti was revoked (RFC 7009), when the opt-in
        # denylist is enabled. A state-store outage fails open (see token_denylist).
        if settings.tokens.denylist_enabled:
            jti = claims.get("jti")
            if isinstance(jti, str) and jafaal_token_denylist.is_access_token_denied(jti):
                raise jafaal_exceptions.InvalidTokenError("Access token has been revoked")

        if settings.sessions.strict_binding:
            self._enforce_session_binding(sid, user_id)

        if settings.tokens.reauthorize_scopes_per_request:
            scope = self._narrow_to_current_entitlement(scope, user)

        return self._build_principal(
            user,
            scope,
            AccessTokenCred(session_id=sid),
        )

    @staticmethod
    def _narrow_to_current_entitlement(
        token_scopes: list[str],
        user: jafaal_ports.UserProtocol,
    ) -> list[str]:
        """Intersect a token's scopes with what the account is entitled to *now*.

        Scopes are stamped into the access token when it is minted, so demoting
        an administrator (or otherwise narrowing their rights) normally has no
        effect until the token expires. With
        :attr:`~jafaal.settings.AuthSettings.reauthorize_scopes_per_request` the
        token's grant is re-checked against what the host's
        :class:`~jafaal.ports.ScopeResolver` grants the account on this request,
        so a demotion applies immediately.

        The result is an **intersection**, never a union: a token can only ever
        lose authority here. Re-deriving the grant outright would *add* scopes a
        promoted user's older token never carried, which is a privilege change no
        issued credential should silently pick up.

        Args:
            token_scopes: Scopes carried by the presented access token.
            user: The freshly loaded account.

        Returns:
            The scopes still backed by the account's current entitlement.
        """
        entitled = set(jafaal_ports.get_scope_resolver().scopes_for(user))
        narrowed = [scope for scope in token_scopes if scope in entitled]
        if len(narrowed) != len(token_scopes):
            dropped = sorted(set(token_scopes) - entitled)
            logger.info(
                f"Access token scopes narrowed to the account's current entitlement: dropped {dropped}",
                extra={"user_id": user.id, "dropped_scopes": dropped},
            )
        return narrowed

    def resolve_from_api_key(
        self,
        raw_key: str,
        request: Request,
    ) -> Principal:
        """Validate a raw API key and return a Principal.

        Args:
            raw_key: The plain-text API key from the
                ``X-API-Key`` header or ``?api_key=``
                query parameter.
            request: The current HTTP request (used for
                audit logging).

        Returns:
            Principal: Resolved principal with an
                :class:`~jafaal.principal.ApiKeyCred`.

        Raises:
            JafaalError: 401 if the key is not found,
                revoked, or expired.
        """
        # Try each candidate digest: primary subkey first, then one per
        # ``secret_key_fallbacks`` entry. A stored digest is keyed by whichever
        # secret_key was primary when the key was minted, so a single lookup
        # would make every existing API key stop working the moment that key is
        # rotated — silently and unrecoverably, since an API key (unlike a
        # session) is never rewritten on its own.
        candidates = jafaal_api_keys_utils.api_key_digests(raw_key)
        primary_hash = candidates[0]
        db_key = None
        matched_hash = primary_hash
        for candidate in candidates:
            db_key = jafaal_api_keys_crud.get_api_key_by_hash(candidate, self._db)
            if db_key is not None:
                matched_hash = candidate
                break

        if db_key is None:
            jafaal_audit.record(
                jafaal_audit.Event.API_KEY_AUTH_FAILURE,
                outcome=jafaal_audit.Outcome.FAILURE,
                level=logging.WARNING,
                ip=network.get_ip_address(request),
                endpoint=request.url.path,
                reason="unknown_or_invalid_key",
            )
            raise jafaal_exceptions.InvalidApiKeyError("Invalid API key")

        user = jafaal_user_guards.get_user_by_id_or_404(db_key.user_id, self._db)
        jafaal_user_guards.check_user_is_active(user)

        if not db_key.is_active:
            raise jafaal_exceptions.InvalidApiKeyError("API key has been revoked")

        if db_key.expires_at is not None and datetime.now(UTC) > timeutils.ensure_aware_utc(db_key.expires_at):
            raise jafaal_exceptions.InvalidApiKeyError("API key has expired")

        # Located via a rotation fallback: rewrite the digest under the primary
        # subkey so the key keeps working once the old secret is dropped.
        if not hmac.compare_digest(matched_hash, primary_hash):
            try:
                jafaal_api_keys_crud.rekey_api_key_digest(db_key.id, primary_hash, self._db)
            except SQLAlchemyError as err:
                logger.warning(f"Failed to re-key API key {db_key.id} digest: {err}", exc_info=err)

        # Best-effort last_used_at update; never fails the request.
        try:
            jafaal_api_keys_crud.update_last_used(db_key.id, self._db)
        except SQLAlchemyError as err:
            logger.warning(f"Failed to update last_used_at for API key {db_key.id}: {err}", exc_info=err)

        logger.info(
            "API key authenticated",
            extra={
                "key_prefix": db_key.key_prefix,
                "user_id": db_key.user_id,
                "endpoint": request.url.path,
                "ip": network.get_ip_address(request),
            },
        )
        jafaal_audit.record(
            jafaal_audit.Event.API_KEY_AUTH_SUCCESS,
            user_id=db_key.user_id,
            key_prefix=db_key.key_prefix,
            endpoint=request.url.path,
            ip=network.get_ip_address(request),
        )

        scopes = jafaal_api_keys_utils.json_to_scopes(db_key.scopes)
        return self._build_principal(
            user,
            scopes,
            ApiKeyCred(
                api_key_id=db_key.id,
                key_prefix=db_key.key_prefix,
            ),
        )

    def resolve_from_session_cookie(
        self,
        session_id: str,
    ) -> Principal:
        """Validate a session ID and return a Principal.

        Args:
            session_id: The session identifier from the
                cookie or token ``sid`` claim.

        Returns:
            Principal: Resolved principal with a
                :class:`~jafaal.principal.SessionCookieCred`.

        Raises:
            JafaalError: 401 if the session is not
                found or has expired.
        """
        db_session = jafaal_sessions_crud.get_session_by_id_not_expired(session_id, self._db)
        if db_session is None:
            raise jafaal_exceptions.SessionExpiredError("Session not found or expired")

        user = jafaal_user_guards.get_user_by_id_or_404(db_session.user_id, self._db)
        jafaal_user_guards.check_user_is_active(user)

        return self._build_principal(
            user,
            [],
            SessionCookieCred(session_id=session_id),
        )

    def issue_token_pair(
        self,
        user: jafaal_ports.UserProtocol,
        session_id: str | None = None,
    ) -> tuple[str, datetime, str, datetime, str, str]:
        """Issue an access/refresh token pair for a user.

        Args:
            user: The validated user object.
            session_id: Optional existing session
                identifier; a new UUID is generated
                when ``None``.

        Returns:
            tuple: ``(session_id, access_token_exp,
                access_token, refresh_token_exp,
                refresh_token, csrf_token)``.
        """
        return jafaal_utils.create_tokens(user, self._token_manager, session_id)

    def revoke_session(
        self,
        session_id: str,
        user_id: UserId,
    ) -> None:
        """Revoke and delete a session.

        Args:
            session_id: The session to revoke.
            user_id: Owner of the session (used to
                prevent cross-user revocations).

        Raises:
            JafaalError: 404 if the session is not
                found for this user.
        """
        jafaal_sessions_crud.delete_session(session_id, user_id, self._db)

    def check_scope(
        self,
        principal: Principal,
        required_scopes: frozenset[str],
    ) -> None:
        """Assert that the principal holds all required scopes.

        Args:
            principal: The authenticated principal.
            required_scopes: Scope strings that must all
                be present in ``principal.scopes``.

        Raises:
            JafaalError: 403 if any required scope is
                missing.
        """
        missing = required_scopes - principal.scopes
        if missing:
            jafaal_audit.record(
                jafaal_audit.Event.SCOPE_DENIED,
                outcome=jafaal_audit.Outcome.BLOCKED,
                level=logging.WARNING,
                user_id=principal.user_id,
                missing=sorted(missing),
                required=sorted(required_scopes),
            )
            raise jafaal_exceptions.MissingScopeError(
                f"Unauthorized Access - Missing permissions: {' '.join(sorted(missing))}",
                missing=missing,
                required=required_scopes,
            )

    def validate_and_hash_password(
        self,
        password: str,
        min_length: int,
        password_type: str,
        max_length: int | None = None,
    ) -> str:
        """Validate password policy and return a secure hash.

        Args:
            password: Plaintext password to validate and hash.
            min_length: Minimum configured password length.
            password_type: Configured password policy type.
            max_length: Maximum accepted length, or ``None`` for no maximum.

        Returns:
            Secure password hash.

        Raises:
            PasswordPolicyError: 422 if the password fails the configured policy.
        """
        self._password_hasher.validate_password(
            password,
            min_length,
            password_type,
            max_length,
        )
        # NIST SP 800-63B: screen against a breach corpus / blocklist after the
        # cheap local policy passes and before hashing. No-op unless the host
        # installs a checker via jafaal.configure_password_breach_checker(...).
        if jafaal_ports.get_password_breach_checker().is_breached(password):
            raise jafaal_exceptions.PasswordPolicyError(
                "This password has appeared in a known data breach; choose a different one."
            )
        return self._password_hasher.hash_password(password)

    def hash_password(self, password: str) -> str:
        """Return a secure hash for a trusted generated secret.

        Args:
            password: Plaintext password or generated secret.

        Returns:
            Secure hash.
        """
        return self._password_hasher.hash_password(password)

    def verify_password(
        self,
        password: str,
        password_hash: str,
    ) -> bool:
        """Verify a plaintext password against a stored hash.

        Args:
            password: Plaintext password supplied by the caller.
            password_hash: Stored password hash.

        Returns:
            True if the password matches, False otherwise.
        """
        return self._password_hasher.verify_password(password, password_hash)

    def get_password_hash(self, user_id: UserId) -> str | None:
        """Return a user's stored local password hash, or ``None``.

        ``None`` means the account has no local password (for example an
        SSO-only account).

        Args:
            user_id: ID of the user to read the credential for.

        Returns:
            The stored password hash, or ``None`` if no credential exists.
        """
        credential = jafaal_credentials_crud.get_credential(user_id, self._db)
        return credential.password_hash if credential is not None else None

    def has_local_password(self, user_id: UserId) -> bool:
        """Return whether a user has a local password credential.

        ``False`` means the account is SSO-only (no row in
        ``users_local_credentials``). The password hash itself is never
        exposed; only this derived boolean is returned.

        Args:
            user_id: ID of the user to check the credential for.

        Returns:
            True if a local credential row exists, False otherwise.
        """
        return jafaal_credentials_crud.get_credential(user_id, self._db) is not None

    def set_local_password_hash(self, user_id: UserId, password_hash: str) -> None:
        """Insert or update a user's local password hash.

        Args:
            user_id: ID of the user to write the credential for.
            password_hash: Argon2/bcrypt password hash to store.

        Returns:
            None.
        """
        jafaal_credentials_crud.upsert_password_hash(user_id, password_hash, self._db)

    def clear_local_password(self, user_id: UserId) -> None:
        """Remove a user's local password credential, if present.

        Args:
            user_id: ID of the user whose credential should be removed.

        Returns:
            None.
        """
        jafaal_credentials_crud.delete_credential(user_id, self._db)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def get_identity_service(
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    password_hasher: Annotated[
        jafaal_password_hasher.PasswordHasher,
        Depends(jafaal_password_hasher.get_password_hasher),
    ],
) -> IdentityService:
    """FastAPI dependency that yields a per-request IdentityService.

    A new :class:`DefaultIdentityService` is constructed for every
    request.  Never use a module-level singleton.

    The resolved :class:`~jafaal.principal.Principal` should be cached
    on ``request.state.principal`` by the caller so that downstream
    dependencies within the same request do not trigger extra database
    lookups.

    Args:
        db: SQLAlchemy database session (from ``get_db``).
        token_manager: JWT token manager.
        password_hasher: Argon2/bcrypt password hasher.

    Returns:
        IdentityService: A fresh ``DefaultIdentityService`` instance
            bound to this request's dependencies.
    """
    return DefaultIdentityService(db, token_manager, password_hasher)
