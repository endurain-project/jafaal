"""WebAuthn (passkey) HTTP endpoints.

Two routers:

* :data:`router` (mounted under ``/auth/webauthn``): passkey *registration* and
  *management* for the authenticated user, plus the anonymous *second-factor*
  ceremony that completes a password-verified pending login.
* :data:`public_router` (mounted under ``/public/webauthn``): the anonymous
  *passwordless authentication* ceremony that issues JAFAAL tokens from a passkey
  assertion alone.

Each endpoint declares its own guard: registration and credential *deletion*
require an access token **plus step-up verification** (they bind and unbind an
authenticator, so a stolen token alone must not suffice); listing credentials
requires only an access token; the authentication and second-factor ceremonies
are anonymous (bound to a one-time challenge and, for the second factor, to the
pending-MFA login).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request, Response, status
from sqlalchemy.orm import Session

import jafaal._internal.internal_dependencies as jafaal_internal_dependencies
import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.services.step_up_service as step_up_service
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
import jafaal.mfa.service as mfa_service
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.settings as jafaal_settings
import jafaal.utils as jafaal_utils
import jafaal.webauthn.challenge_store as webauthn_challenge_store
import jafaal.webauthn.crud as webauthn_crud
import jafaal.webauthn.schema as webauthn_schema
import jafaal.webauthn.service as webauthn_service
from jafaal._core import network

logger = logging.getLogger(__name__)

router = jafaal_orm.auth_router()
public_router = jafaal_orm.auth_router()

_TokenResponse = (
    jafaal_schema.AuthorizationRedirectResponse | jafaal_schema.TokenResponseWeb | jafaal_schema.TokenResponseMobile
)


# ===========================================================================
# Registration (authenticated user)
# ===========================================================================


@router.post("/register/begin", status_code=status.HTTP_200_OK)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def begin_registration(
    request: Request,
    data: webauthn_schema.WebAuthnRegistrationBegin,
    token_user_id: Annotated[
        jafaal_orm.UserId,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Start a passkey registration ceremony for the authenticated user.

    Requires step-up verification: a passkey is a login credential in its own
    right, so binding one is an authenticator-binding operation, not a profile
    edit. An SSO-only account with no local factor is challenged to
    re-authenticate at its identity provider rather than being waved through —
    unlike TOTP enrolment, registration has no bootstrap exemption, because a
    federated account always has a provider to re-authenticate against.

    Returns the ``navigator.credentials.create()`` options; the challenge is
    stored server-side, keyed to this user, and redeemed once by
    ``/register/complete``.
    """
    step_up_service.verify_step_up_credentials(
        token_user_id,
        data.current_password,
        data.mfa_code,
        identity_service,
        step_up_store,
        db,
    )
    user = jafaal_user_guards.get_user_by_id_or_404(token_user_id, db)
    return webauthn_service.begin_registration(user, db)


@router.post(
    "/register/complete",
    response_model=webauthn_schema.WebAuthnCredentialRead,
    status_code=status.HTTP_201_CREATED,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def complete_registration(
    request: Request,
    data: webauthn_schema.WebAuthnRegistrationComplete,
    token_user_id: Annotated[
        jafaal_orm.UserId,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> webauthn_schema.WebAuthnCredentialRead:
    """Finish a passkey registration ceremony and store the credential.

    Carries no step-up fields of its own: it can only succeed against the
    single-use, user-keyed challenge minted by ``/register/begin``, which is
    already step-up gated.
    """
    user = jafaal_user_guards.get_user_by_id_or_404(token_user_id, db)
    credential = webauthn_service.complete_registration(user, data.credential, data.label, db)
    jafaal_audit.record(
        jafaal_audit.Event.WEBAUTHN_REGISTERED,
        user_id=user.id,
        credential_pk=credential.id,
    )
    jafaal_ports.dispatch_event(
        "on_authenticator_changed",
        jafaal_ports.AuthenticatorChanged(
            user_id=user.id,
            username=user.username,
            factor="passkey",
            change="added",
            remaining_factors=len(webauthn_crud.get_credentials_by_user_id(user.id, db)),
        ),
    )
    return webauthn_schema.WebAuthnCredentialRead.model_validate(credential)


# ===========================================================================
# Credential management (authenticated user)
# ===========================================================================


@router.get(
    "/credentials",
    response_model=list[webauthn_schema.WebAuthnCredentialRead],
    status_code=status.HTTP_200_OK,
)
def list_credentials(
    token_user_id: Annotated[
        jafaal_orm.UserId,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[webauthn_schema.WebAuthnCredentialRead]:
    """List the authenticated user's registered passkeys."""
    credentials = webauthn_crud.get_credentials_by_user_id(token_user_id, db)
    return [webauthn_schema.WebAuthnCredentialRead.model_validate(cred) for cred in credentials]


@router.post("/credentials/{credential_pk}/delete", status_code=status.HTTP_204_NO_CONTENT)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def delete_credential(
    request: Request,
    credential_pk: int,
    data: webauthn_schema.WebAuthnCredentialDelete,
    token_user_id: Annotated[
        jafaal_orm.UserId,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """Delete one of the authenticated user's passkeys.

    Requires step-up verification, at the same assurance as registering one:
    removing an authenticator is how an attacker holding a stolen token would
    strip the account's factors (NIST SP 800-63B §6.1.4).

    Modelled as ``POST .../delete`` rather than ``DELETE`` because the step-up
    proof has to travel in a request body, and a body on ``DELETE`` is poorly
    supported — several HTTP clients (httpx's ``.delete()`` among them) offer no
    way to send one, and intermediaries may strip it.
    """
    step_up_service.verify_step_up_credentials(
        token_user_id,
        data.current_password,
        data.mfa_code,
        identity_service,
        step_up_store,
        db,
    )
    credential = webauthn_crud.get_credential_by_pk(credential_pk, token_user_id, db)
    if credential is None:
        raise jafaal_exceptions.NotFoundError("Passkey not found.")
    webauthn_crud.delete_credential(credential, db)
    jafaal_audit.record(
        jafaal_audit.Event.WEBAUTHN_CREDENTIAL_DELETED,
        level=logging.WARNING,
        user_id=token_user_id,
        credential_pk=credential_pk,
    )
    user = jafaal_user_guards.get_user_by_id_or_404(token_user_id, db)
    jafaal_ports.dispatch_event(
        "on_authenticator_changed",
        jafaal_ports.AuthenticatorChanged(
            user_id=token_user_id,
            username=user.username,
            factor="passkey",
            change="removed",
            remaining_factors=len(webauthn_crud.get_credentials_by_user_id(token_user_id, db)),
        ),
    )


# ===========================================================================
# Second factor (anonymous; completes a password-verified pending login)
# ===========================================================================


@router.post("/mfa/begin", status_code=status.HTTP_200_OK)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def begin_second_factor(
    request: Request,
    data: webauthn_schema.WebAuthnSecondFactorBegin,
    pending_mfa_store: Annotated[
        jafaal_security_stores.PendingMFAStore,
        Depends(jafaal_security_stores.get_pending_mfa_store),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Start a second-factor passkey ceremony for a pending login.

    Returns the ``navigator.credentials.get()`` options. When the ticket does not
    address a live pending login an empty allow-list is returned, so the endpoint
    never discloses whether a login is pending or which passkeys an account
    holds; the ceremony simply cannot be completed.
    """
    pending = pending_mfa_store.get_pending_login(data.mfa_token)
    return webauthn_service.begin_second_factor(
        data.mfa_token,
        pending.user_id if pending is not None else None,
        db,
    )


@router.post("/mfa/complete", response_model=_TokenResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def complete_second_factor(
    response: Response,
    request: Request,
    data: webauthn_schema.WebAuthnSecondFactorComplete,
    failed_attempts: Annotated[
        jafaal_security_stores.FailedLoginStore,
        Depends(jafaal_security_stores.get_failed_login_attempts),
    ],
    pending_mfa_store: Annotated[
        jafaal_security_stores.PendingMFAStore,
        Depends(jafaal_security_stores.get_pending_mfa_store),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Verify a second-factor passkey assertion and complete the login."""
    client = authorization_code_service.resolve_login_client(data.client_id, request)
    # The ticket is the caller's proof that it satisfied the password factor;
    # resolving the pending login from it (rather than from a public username)
    # is what keeps this a genuine second factor.
    pending = pending_mfa_store.get_pending_login(data.mfa_token)
    challenge = webauthn_challenge_store.pop_second_factor_challenge(data.mfa_token)
    if pending is None or challenge is None:
        logger.warning("No pending WebAuthn second-factor login for the presented ticket")
        raise jafaal_exceptions.InvalidRequestError("No pending login found. Please start the login again.")

    user_id = pending.user_id
    username = pending.username
    username_log_id = jafaal_security_stores.username_log_identifier(username)

    if pending_mfa_store.is_locked_out(username):
        lockout_until = pending_mfa_store.get_lockout_time(username)
        if lockout_until:
            seconds_remaining = int((lockout_until - datetime.now(UTC)).total_seconds())
            raise jafaal_exceptions.RateLimitedError(
                f"Too many failed MFA attempts. Account locked for {seconds_remaining} seconds.",
                retry_after=seconds_remaining,
            )

    if not webauthn_service.complete_second_factor(user_id, data.credential, challenge, db):
        failed_count = pending_mfa_store.record_failed_attempt(username)
        logger.warning("Invalid WebAuthn second factor for %s. Failed attempts: %s", username_log_id, failed_count)
        jafaal_audit.record(
            jafaal_audit.Event.WEBAUTHN_AUTH_FAILURE,
            outcome=jafaal_audit.Outcome.FAILURE,
            level=logging.WARNING,
            user_id=user_id,
            username=username,
            ip=network.get_ip_address(request),
            failed_attempts=failed_count,
            ceremony="second_factor",
        )
        raise jafaal_exceptions.InvalidCredentialsError("WebAuthn authentication failed.")

    claimed = pending_mfa_store.claim_pending_login(data.mfa_token)
    if claimed is None or claimed.user_id != user_id:
        logger.warning("Pending WebAuthn login for %s was missing or already claimed", username_log_id)
        raise jafaal_exceptions.InvalidRequestError("No pending login found. Please start the login again.")

    # Same client the password step was started for — see the TOTP path.
    if claimed.client_id != client.client_id:
        logger.warning("Pending WebAuthn login for %s was claimed by a different client", username_log_id)
        raise jafaal_exceptions.InvalidRequestError(
            "This login was started for a different client. Please start the login again."
        )

    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
    if not user:
        logger.warning("User ID %s not found during WebAuthn second-factor verification", user_id)
        raise jafaal_exceptions.AuthenticationError("Unable to authenticate")
    jafaal_user_guards.check_user_is_active(user)

    pending_mfa_store.reset_attempts(username)
    failed_attempts.reset_attempts(username)
    failed_attempts.reset_ip_attempts(network.get_ip_address(request))

    jafaal_audit.record(
        jafaal_audit.Event.WEBAUTHN_AUTH_SUCCESS,
        user_id=user_id,
        username=username,
        ip=network.get_ip_address(request),
        ceremony="second_factor",
    )
    # Scope and the authorization request being completed come from the claimed
    # ticket — the password step is where the client asked — so completing with a
    # passkey cannot widen the grant or redirect it somewhere else.
    if claimed.auth_request is not None:
        oauth_state = authorization_code_service.resolve_authorization_request(claimed.auth_request, client, db)
        jafaal_utils.apply_no_store(response)
        return authorization_code_service.complete_local_authorization(oauth_state, user, request, db)
    return jafaal_utils.complete_login(response, request, user, client, token_manager, db, claimed.scope)


# ===========================================================================
# Passwordless authentication (anonymous)
# ===========================================================================


@public_router.post("/authenticate/begin", response_model=webauthn_schema.WebAuthnAuthenticationBeginResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def begin_authentication(
    request: Request,
    data: webauthn_schema.WebAuthnAuthenticationBegin,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> webauthn_schema.WebAuthnAuthenticationBeginResponse:
    """Start a passwordless authentication ceremony.

    Returns the ``navigator.credentials.get()`` options plus an opaque
    ``challenge_id`` to echo back to ``/authenticate/complete``.
    """
    challenge_id, options = webauthn_service.begin_authentication(data.username, db)
    return webauthn_schema.WebAuthnAuthenticationBeginResponse(challenge_id=challenge_id, options=options)


@public_router.post("/authenticate/complete", response_model=_TokenResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def complete_authentication(
    response: Response,
    request: Request,
    data: webauthn_schema.WebAuthnAuthenticationComplete,
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Verify a passwordless passkey assertion and issue JAFAAL tokens.

    The ceremony always demands user verification, so a successful assertion
    proves possession of the authenticator *and* a PIN/biometric — two factors,
    which is why it completes a login on its own by default. A deployment whose
    policy names TOTP specifically can set
    ``WebAuthnSettings.passkey_login_satisfies_mfa=False``, which refuses this
    shortcut for an account that has TOTP enrolled and sends it to the password
    + TOTP flow instead.
    """
    client = authorization_code_service.resolve_login_client(data.client_id, request)
    user = webauthn_service.complete_authentication(data.challenge_id, data.credential, db)
    jafaal_user_guards.check_user_is_active(user)

    if not jafaal_settings.get_settings().webauthn.passkey_login_satisfies_mfa and mfa_service.is_mfa_enabled_for_user(
        user.id, db
    ):
        # Refused *after* the assertion verified: the account exists and the
        # passkey is genuine, so there is nothing left to disclose, and the
        # caller needs to be told which flow to use instead.
        logger.info("Passwordless login refused for a TOTP-enrolled account (passkey_login_satisfies_mfa=False)")
        jafaal_audit.record(
            jafaal_audit.Event.WEBAUTHN_AUTH_FAILURE,
            outcome=jafaal_audit.Outcome.BLOCKED,
            level=logging.WARNING,
            user_id=user.id,
            username=user.username,
            ip=network.get_ip_address(request),
            ceremony="passwordless",
            reason="mfa_required_by_policy",
        )
        raise jafaal_exceptions.AuthorizationError(
            "This account requires multi-factor authentication. Sign in with your password and MFA code."
        )

    jafaal_audit.record(
        jafaal_audit.Event.WEBAUTHN_AUTH_SUCCESS,
        user_id=user.id,
        username=user.username,
        ip=network.get_ip_address(request),
        ceremony="passwordless",
    )
    return jafaal_utils.complete_login(response, request, user, client, token_manager, db)
