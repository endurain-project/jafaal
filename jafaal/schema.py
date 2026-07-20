"""Pydantic schemas for the authentication module."""

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
)


class LoginRequest(BaseModel):
    """
    Schema for login requests containing username and password.

    Attributes:
        username: Username of the user.
        password: User password.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: StrictStr = Field(..., min_length=1, max_length=250)
    password: StrictStr = Field(..., min_length=8)


class SignUpRequest(BaseModel):
    """Minimal local sign-up request.

    JAFAAL only needs credentials to create the account and its password; any
    additional profile fields a host collects at sign-up are the host's own
    concern (its ``UserRepository`` fills them). ``username``/``email`` are
    passed to the host repository as supplied.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: StrictStr = Field(..., min_length=1, max_length=250)
    email: StrictStr = Field(..., min_length=3, max_length=250)
    password: StrictStr = Field(..., min_length=8)


class MFALoginRequest(BaseModel):
    """
    Schema for MFA login requests.

    Attributes:
        username: Username of the user attempting to log in.
        mfa_code: Either a 6-digit TOTP code or a backup code.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: StrictStr = Field(..., min_length=1, max_length=250)
    mfa_code: StrictStr = Field(
        ...,
        pattern=r"^(\d{6}|[A-Z0-9]{4}-[A-Z0-9]{4})$",
    )


class StepUpVerification(BaseModel):
    """Generic step-up verification payload.

    Used by sensitive account-level operations (API-key creation, MFA
    backup-code regeneration, IdP unlink, ...) to require fresh proof of
    identity beyond a valid access token. For SSO-only accounts (no local
    password) the ``current_password`` field may be omitted and the password
    check is skipped.

    Attributes:
        current_password: Caller's existing password. Required when the account
            has a local password; may be omitted for SSO-only accounts.
        mfa_code: TOTP or backup code, required when MFA is enabled.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    current_password: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=250,
        description="Current password (step-up verification). Required when the account has a local password.",
    )
    mfa_code: StrictStr | None = Field(
        default=None,
        max_length=32,
        description="TOTP or backup code, required when MFA is enabled",
    )


class MFARequiredResponse(BaseModel):
    """
    Response indicating MFA verification is required.

    Attributes:
        mfa_required: Indicates whether MFA is required.
        username: Username for which MFA is required.
        message: Message describing the requirement.
    """

    model_config = ConfigDict(extra="forbid")

    mfa_required: StrictBool = True
    username: StrictStr
    message: StrictStr = "MFA verification required"


class MobileSessionResponse(BaseModel):
    """
    Response for mobile password login with PKCE exchange flow.

    Attributes:
        session_id: Session identifier for token exchange.
        mfa_required: Whether MFA is required.
        message: Instructions for the client on next steps.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: StrictStr
    mfa_required: StrictBool = False
    message: StrictStr = "Complete authentication by exchanging tokens at /public/idp/session/{session_id}/tokens"


class TokenResponseWeb(BaseModel):
    """
    Token response payload for web clients.

    Attributes:
        session_id: Session identifier.
        access_token: Bearer access token.
        csrf_token: CSRF token bound to the session.
        token_type: Always ``bearer``.
        expires_in: Seconds until the access token expires.
        refresh_token_expires_in: Seconds until the refresh token expires.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: StrictStr
    access_token: StrictStr
    csrf_token: StrictStr
    token_type: Literal["bearer"] = "bearer"
    expires_in: StrictInt
    refresh_token_expires_in: StrictInt


class TokenResponseMobile(BaseModel):
    """
    Token response payload for mobile clients.

    Attributes:
        session_id: Session identifier.
        access_token: Bearer access token.
        refresh_token: Refresh token.
        token_type: Always ``bearer``.
        expires_in: Seconds until the access token expires.
        refresh_token_expires_in: Seconds until the refresh token expires.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: StrictStr
    access_token: StrictStr
    refresh_token: StrictStr
    token_type: Literal["bearer"] = "bearer"
    expires_in: StrictInt
    refresh_token_expires_in: StrictInt


class LogoutResponse(BaseModel):
    """
    Response payload returned by the logout endpoint.

    Attributes:
        message: Human-readable confirmation message.
    """

    model_config = ConfigDict(extra="forbid")

    message: StrictStr
