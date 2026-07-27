"""Sign-up tokens router for user registration."""

from typing import Annotated

from fastapi import (
    Depends,
    Request,
)
from sqlalchemy.orm import Session

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.sign_up_tokens.schema as sign_up_tokens_schema
import jafaal.sign_up_tokens.utils as sign_up_tokens_utils

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
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
) -> sign_up_tokens_schema.SignUpResponse:
    """
    Handle user sign-up request.

    Args:
        request: Incoming HTTP request.
        user: Sign-up payload (username, email, password).
        identity_service: Injected identity service.
        db: Database session.

    Returns:
        Sign-up result with message and flags.

    Raises:
        JafaalError: 403 if sign-up is disabled.
    """
    signup_config = jafaal_ports.get_settings_provider().get_signup_config()

    # Check if signup is enabled
    if not signup_config.enabled:
        raise jafaal_exceptions.AuthorizationError("User sign-up is not enabled on this server")

    # Create the user (host provisions its own row + defaults via UserRepository)
    created_user = sign_up_tokens_utils.register_local_user(user, signup_config, identity_service, db)

    # Return appropriate response based on the sign-up configuration
    message = "User created successfully."
    email_verification_required: bool | None = None
    admin_approval_required: bool | None = None

    if signup_config.require_email_verification:
        await sign_up_tokens_utils.request_email_verification(created_user, db)
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
    )


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
