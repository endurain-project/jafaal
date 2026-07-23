"""Auth-owned step-up verification with progressive lockout."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.credentials.crud as jafaal_credentials_crud
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as jafaal_identity_links_crud
import jafaal.mfa.service as mfa_service
import jafaal.settings as jafaal_settings
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from jafaal.identity_service import IdentityService


def _step_up_key(user_id: UserId) -> str:
    """
    Build the lockout key for a user's step-up attempts.

    Args:
        user_id: Authenticated user ID.

    Returns:
        Stable string key for lockout tracking.

    Raises:
        None.
    """
    return f"user:{user_id}"


def _eligible_reauth_idp_ids(user_id: UserId, db: Session) -> list[int]:
    """Return the identity-provider ids a user may re-authenticate against.

    Used to decide whether an account with no local factor can be *challenged*
    to re-authenticate at its identity provider (non-empty list) or must fail
    closed (empty). Empty when IdP step-up re-auth is disabled, the user has no
    identity-provider links, or none of those providers is currently enabled.

    Args:
        user_id: The authenticated user.
        db: SQLAlchemy database session.

    Returns:
        The enabled, linked identity-provider ids (possibly empty).
    """
    if not jafaal_settings.get_settings().step_up_idp_reauth_enabled:
        return []
    links = jafaal_identity_links_crud.get_user_identity_providers_by_user_id(user_id, db)
    if not links:
        return []
    enabled_ids = {idp.id for idp in idp_crud.get_enabled_identity_providers(db)}
    return [link.idp_id for link in links if link.idp_id in enabled_ids]


def verify_step_up_credentials(
    user_id: UserId,
    current_password: str | None,
    mfa_code: str | None,
    identity_service: IdentityService,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
    *,
    allow_sso_only_bootstrap: bool = False,
) -> None:
    """
    Enforce step-up verification for sensitive account operations.

    A valid access token alone is not sufficient authorisation for
    operations that grant persistent account access (password
    change, API-key creation, MFA enrolment, MFA backup-code
    regeneration, MFA disable, etc.). This function requires the
    caller to re-prove possession of the current password and —
    when MFA is enabled — a fresh TOTP or backup code.

    Accepted factors (in precedence order)
    --------------------------------------
    1. A single-use **IdP re-authentication grant** (see the SSO step-up flow):
       consuming it satisfies step-up regardless of password/MFA, because the
       second factor was delegated to, and freshly asserted by, the identity
       provider. This is what lets an SSO-only account step up without local MFA.
    2. The account's **local password**, when it has one.
    3. A **TOTP/backup MFA code**, when MFA is enabled.

    Fail-closed / IdP re-auth challenge
    -----------------------------------
    An account may have no local password (SSO-only: no row in
    ``users_local_credentials``) and no MFA. A valid access token alone must not
    satisfy step-up — otherwise a stolen token (e.g. exfiltrated via XSS) could
    perform account-takeover-adjacent operations — so:

    * if the account has at least one usable identity-provider link (and IdP
      step-up re-auth is enabled), a
      :class:`~jafaal.exceptions.StepUpReauthRequiredError` is raised so the
      client starts a fresh IdP re-authentication (which mints the grant above),
      and then retries; otherwise
    * step-up **fails closed** (403) unless ``allow_sso_only_bootstrap`` is set.

    The one bootstrap exception is MFA *enrolment* (``enable_mfa``), which passes
    ``allow_sso_only_bootstrap=True``. Enrolment lets an SSO-only user establish
    their first local factor, and it independently proves possession of the
    freshly-enrolled TOTP code, so it does not rely on this check.

    Failed verifications are tracked per-user with progressive
    lockout: 5 failures → 5 min, 10 → 30 min, 15 → 2 hours.
    Lockout is checked before any password or MFA comparison so
    that incorrect-guess enumeration is bounded even when the
    attacker has a valid access token. The fail-closed denial and the re-auth
    challenge are deterministic account-state checks (not wrong guesses), so
    they do not count toward lockout.

    Args:
        user_id: ID of the authenticated user.
        current_password: The user's current password as supplied
            in the request body. Verified only when the account has a
            local password; may be ``None`` for SSO-only accounts.
        mfa_code: TOTP or backup code, required when MFA is
            enabled. Ignored when MFA is disabled.
        identity_service: Identity service dependency.
        step_up_store: Step-up lockout store.
        db: SQLAlchemy database session.
        allow_sso_only_bootstrap: When ``True``, permit an account
            that has neither a local password nor MFA to pass this
            check (the MFA-enrolment bootstrap). Defaults to ``False``
            so every other sensitive operation fails closed.

    Returns:
        None.

    Raises:
        JafaalError: 429 if the user is currently locked out; 401
            (``step_up_reauth_required``) if the account has no local factor but
            can re-authenticate at a linked identity provider; 403 if it has no
            factor and no usable IdP link (and ``allow_sso_only_bootstrap`` is
            not set); 401 if the current password is wrong, is missing for an
            account that has one, or when MFA is enabled and the supplied code is
            missing or invalid.
    """
    key = _step_up_key(user_id)

    if step_up_store.is_locked_out(key):
        lockout_until = step_up_store.get_lockout_time(key)
        retry_after = 0
        if lockout_until is not None:
            from datetime import UTC, datetime

            remaining = lockout_until - datetime.now(UTC)
            retry_after = max(0, int(remaining.total_seconds()))
        logger.warning(f"Step-up blocked for user {user_id}: locked out")
        raise jafaal_exceptions.RateLimitedError(
            "Too many failed step-up attempts. Try again later.",
            retry_after=retry_after,
        )

    # Guard: ensure the user exists (raises 404 otherwise).
    jafaal_user_guards.get_user_by_id_or_404(user_id, db)

    # Highest-precedence factor: a single-use grant from a fresh IdP
    # re-authentication (the SSO step-up flow). Consuming it satisfies step-up
    # regardless of password/MFA — the second factor was delegated to, and
    # freshly asserted by, the identity provider.
    if jafaal_security_stores.consume_step_up_reauth_grant(user_id):
        logger.info(f"Step-up satisfied for user {user_id} via a fresh IdP re-authentication grant")
        step_up_store.reset_attempts(key)
        return

    credential = jafaal_credentials_crud.get_credential(user_id, db)
    mfa_enabled = mfa_service.is_mfa_enabled_for_user(user_id, db)

    # Fail closed: an account with neither a local password nor MFA has no
    # factor the server can challenge, so a valid access token alone would
    # otherwise satisfy step-up. Deny unless this is the MFA-enrolment
    # bootstrap (see the docstring). This is a deterministic account-state
    # check, not a wrong guess, so it does not touch the lockout counter.
    if credential is None and not mfa_enabled and not allow_sso_only_bootstrap:
        reauth_idp_ids = _eligible_reauth_idp_ids(user_id, db)
        if reauth_idp_ids:
            # The account can delegate step-up to its identity provider(s):
            # signal the client to start a fresh IdP re-authentication (RFC 9470).
            logger.info(f"Step-up for user {user_id}: no local factor; challenging for IdP re-authentication")
            raise jafaal_exceptions.StepUpReauthRequiredError(reauth_idp_ids=reauth_idp_ids)
        logger.warning(f"Step-up denied for user {user_id}: no password, MFA, or usable IdP link to verify")
        raise jafaal_exceptions.AuthorizationError(
            "This operation requires step-up verification, but your account has no password or "
            "multi-factor authentication to verify. Enable multi-factor authentication first."
        )

    if credential is not None:
        if not current_password:
            step_up_store.record_failed_attempt(key)
            raise jafaal_exceptions.InvalidCredentialsError("Step-up verification failed")
        if not identity_service.verify_password(
            current_password,
            credential.password_hash,
        ):
            step_up_store.record_failed_attempt(key)
            raise jafaal_exceptions.InvalidCredentialsError("Step-up verification failed")

    if mfa_enabled:
        if not mfa_code:
            step_up_store.record_failed_attempt(key)
            raise jafaal_exceptions.AuthenticationError("MFA code required for this operation")
        if not mfa_service.verify_user_mfa(user_id, mfa_code, identity_service, db):
            step_up_store.record_failed_attempt(key)
            raise jafaal_exceptions.InvalidCredentialsError("Step-up verification failed")

    # All available factors passed — reset the failure counter.
    step_up_store.reset_attempts(key)
