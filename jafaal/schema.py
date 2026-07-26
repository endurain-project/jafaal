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
        mfa_token: The opaque, single-use ticket returned by ``/auth/login``
            in :class:`MFARequiredResponse`. It proves *this caller* satisfied
            the password factor. The username is deliberately **not** accepted
            here: it is public or guessable, so addressing the pending login by
            username would let anyone holding a valid one-time code finish a
            login that somebody else's password step opened.
        mfa_code: Either a 6-digit TOTP code or a backup code.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    mfa_token: StrictStr = Field(..., min_length=1, max_length=512)
    mfa_code: StrictStr = Field(
        ...,
        pattern=r"^(\d{6}|[A-Z0-9]{4}-[A-Z0-9]{4})$",
    )


class StepUpVerification(BaseModel):
    """Generic step-up verification payload.

    Used by sensitive account-level operations (API-key creation, MFA
    backup-code regeneration, IdP unlink, ...) to require fresh proof of
    identity beyond a valid access token. Accounts with a local password must
    supply ``current_password``; when MFA is enabled an ``mfa_code`` is also
    required. An SSO-only account with no MFA has no factor to verify, so these
    operations are refused until MFA is enrolled — step-up fails closed rather
    than passing on a valid access token alone.

    Attributes:
        current_password: Caller's existing password. Required when the account
            has a local password; may be omitted for SSO-only accounts (which
            must then satisfy step-up via MFA).
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
        mfa_token: Opaque, single-use ticket proving the password factor was
            satisfied by this caller. Hold it in memory (never persist it) and
            present it to ``/auth/mfa/verify`` or the WebAuthn second-factor
            endpoints. It expires in five minutes.
        username: Username for which MFA is required, echoed back for display.
            It is *not* a credential and does not address the pending login.
        message: Message describing the requirement.
    """

    model_config = ConfigDict(extra="forbid")

    mfa_required: StrictBool = True
    mfa_token: StrictStr
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


class TokenIntrospectionResponse(BaseModel):
    """RFC 7662 token introspection response.

    ``active`` is the only guaranteed field; the rest are populated only for an
    active token. ``typ`` and ``sid`` are JAFAAL extensions (the token's own type
    and its session id).

    Attributes:
        active: Whether the token is currently valid.
        sub: Subject (user) identifier.
        scope: Space-delimited granted scopes.
        typ: JAFAAL token type (``access`` or ``refresh``).
        token_type: ``Bearer`` for an active token.
        client_id: OAuth client identifier the token was issued to.
        exp: Expiry (epoch seconds).
        iat: Issued-at (epoch seconds).
        nbf: Not-before (epoch seconds).
        iss: Issuer.
        aud: Audience.
        jti: Token identifier.
        sid: Session identifier (JAFAAL extension).
    """

    model_config = ConfigDict(extra="forbid")

    active: StrictBool
    sub: StrictStr | None = None
    scope: StrictStr | None = None
    typ: StrictStr | None = None
    token_type: StrictStr | None = None
    client_id: StrictStr | None = None
    exp: StrictInt | None = None
    iat: StrictInt | None = None
    nbf: StrictInt | None = None
    iss: StrictStr | None = None
    aud: StrictStr | None = None
    jti: StrictStr | None = None
    sid: StrictStr | None = None


class LogoutResponse(BaseModel):
    """
    Response payload returned by the logout endpoint.

    Attributes:
        message: Human-readable confirmation message.
    """

    model_config = ConfigDict(extra="forbid")

    message: StrictStr
