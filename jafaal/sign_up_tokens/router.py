"""Sign-up tokens router for user registration."""

from typing import Annotated

from fastapi import (
    Depends,
    Query,
    Request,
    Response,
)
from sqlalchemy.orm import Session

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.sign_up_tokens.crud as sign_up_tokens_crud
import jafaal.sign_up_tokens.schema as sign_up_tokens_schema
import jafaal.sign_up_tokens.status_store as sign_up_status_store
import jafaal.sign_up_tokens.utils as sign_up_tokens_utils
import jafaal.utils as jafaal_utils

# Define the API router
router = jafaal_orm.auth_router()


@router.post(
    "/sign-up/request",
    status_code=201,
    response_model=sign_up_tokens_schema.SignUpResponse,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def signup(
    request: Request,
    user: jafaal_schema.SignUpRequest,
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
    status_store: Annotated[
        sign_up_status_store.SignUpStatusStore,
        Depends(sign_up_status_store.get_sign_up_status_store),
    ],
) -> sign_up_tokens_schema.SignUpResponse:
    """
    Handle user sign-up request.

    Args:
        request: Incoming HTTP request.
        user: Sign-up payload (username, email, password).
        identity_service: Injected identity service.
        db: Database session.
        status_store: Ephemeral sign-up status handle store.

    Returns:
        Sign-up result with message and flags.

    Raises:
        JafaalError: 403 if sign-up is disabled.
    """
    signup_config = jafaal_ports.get_settings_provider().get_signup_config()

    # Check if signup is enabled
    if not signup_config.enabled:
        raise jafaal_exceptions.AuthorizationError("User sign-up is not enabled on this server")

    # Create the user (host provisions its own row + defaults via UserRepository).
    # Returns None when the username/email is already registered.
    created_user = sign_up_tokens_utils.register_local_user(user, signup_config, identity_service, db)

    # The response is built from configuration alone, never from whether the
    # account was actually created: an unauthenticated caller must not be able
    # to tell "registered" from "already exists" (OWASP ASVS V2.2.1). The
    # verification email is the only real difference, and it is only ever sent
    # to a genuinely new account.
    message = "User created successfully."
    email_verification_required: bool | None = None
    admin_approval_required: bool | None = None
    signup_handle: str | None = None

    if signup_config.require_email_verification:
        token_id: str | None = None
        if created_user is not None:
            token_id = await sign_up_tokens_utils.request_email_verification_with_reference(created_user, db)
        signup_handle = status_store.create(
            token_id,
            ttl_seconds=sign_up_tokens_utils.SIGN_UP_TOKEN_TTL_SECONDS,
        )
        message += " Email sent with verification instructions."
        email_verification_required = True
    if signup_config.require_admin_approval:
        message += " Account is pending admin approval."
        admin_approval_required = True
    if not signup_config.require_email_verification and not signup_config.require_admin_approval:
        message += " You can now log in."
    return sign_up_tokens_schema.SignUpResponse(
        message=message,
        email_verification_required=email_verification_required,
        admin_approval_required=admin_approval_required,
        signup_handle=signup_handle,
    )


@router.get(
    "/sign-up/status",
    response_model=sign_up_tokens_schema.SignUpStatusResponse,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.POLLING)
def get_signup_status(
    request: Request,
    response: Response,
    handle: Annotated[str, Query(min_length=1, max_length=256)],
    status_store: Annotated[
        sign_up_status_store.SignUpStatusStore,
        Depends(sign_up_status_store.get_sign_up_status_store),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
) -> sign_up_tokens_schema.SignUpStatusResponse:
    """Return whether the email token associated with an opaque handle was confirmed."""
    jafaal_utils.apply_no_store(response)
    found, token_id = status_store.resolve(handle)
    if not found:
        raise jafaal_exceptions.NotFoundError("Sign-up handle not found or expired")
    if token_id is None:
        return sign_up_tokens_schema.SignUpStatusResponse(confirmed=False)

    confirmed = sign_up_tokens_crud.is_sign_up_token_confirmed(token_id, db)
    if confirmed is None:
        raise jafaal_exceptions.NotFoundError("Sign-up handle not found or expired")
    return sign_up_tokens_schema.SignUpStatusResponse(confirmed=confirmed)


@router.post(
    "/sign-up/confirm",
    response_model=sign_up_tokens_schema.SignUpResponse,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def verify_email(
    request: Request,
    confirm_data: sign_up_tokens_schema.SignUpConfirm,
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
) -> sign_up_tokens_schema.SignUpResponse:
    """
    Verify user email via sign-up token.

    Args:
        request: Incoming HTTP request.
        confirm_data: Token confirmation payload.
        db: Database session.

    Returns:
        Verification result with message and optional flags.

    Raises:
        JafaalError: 412 if email verification is not enabled.
    """
    signup_config = jafaal_ports.get_settings_provider().get_signup_config()
    if not signup_config.require_email_verification:
        raise jafaal_exceptions.PreconditionFailedError("Email verification is not enabled")

    # Verify the email; activate now unless admin approval is still required.
    user_id = sign_up_tokens_utils.use_sign_up_token(confirm_data.token, db)
    jafaal_ports.get_user_repository().set_email_verified(
        user_id, db, activate=not signup_config.require_admin_approval
    )

    # Return appropriate response based on the sign-up configuration
    message = "Email verified successfully."
    admin_approval_required: bool | None = None
    if signup_config.require_admin_approval:
        # Ask the host to notify its admins that a new account awaits approval.
        user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
        await sign_up_tokens_utils.notify_pending_admin_approval(user)
        message += " Your account is now pending admin approval."
        admin_approval_required = True
    else:
        message += " You can now log in."
    return sign_up_tokens_schema.SignUpResponse(
        message=message,
        admin_approval_required=admin_approval_required,
    )
