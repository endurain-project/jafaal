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

from jafaal.settings import PASSWORD_FIELD_MAX_LENGTH


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
    # Bounded by the shared transport limit; the policy minimum/maximum comes
    # from PasswordSettings, applied by validate_and_hash_for_user.
    password: StrictStr = Field(..., min_length=1, max_length=PASSWORD_FIELD_MAX_LENGTH)


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
    client_id: StrictStr = Field(
        ...,
        max_length=256,
        description="The registered client the login was started for; decides token delivery and scope.",
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
        max_length=PASSWORD_FIELD_MAX_LENGTH,
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


class TokenResponseWeb(BaseModel):
    """Token response for a client registered with ``token_delivery="cookie"``.

    The RFC 6749 §5.1 response minus ``refresh_token``, which is delivered as an
    ``HttpOnly``, ``SameSite=Strict`` cookie instead (RFC 9700 §7.2: do not hand
    a refresh token to page script). ``session_id``, ``csrf_token`` and
    ``refresh_token_expires_in`` are JAFAAL extensions, which §5.1 permits.

    Attributes:
        session_id: Session identifier.
        access_token: Bearer access token.
        csrf_token: CSRF token bound to the session.
        token_type: Always ``Bearer`` (RFC 6750 §4).
        expires_in: Seconds until the access token expires.
        refresh_token_expires_in: Seconds until the refresh token expires.
        scope: Space-delimited scopes the access token actually carries.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: StrictStr
    access_token: StrictStr
    csrf_token: StrictStr
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: StrictInt
    refresh_token_expires_in: StrictInt
    scope: StrictStr | None = None


class TokenResponseMobile(BaseModel):
    """The RFC 6749 §5.1 token response, for ``token_delivery="body"``.

    Attributes:
        session_id: Session identifier (JAFAAL extension).
        access_token: Bearer access token.
        refresh_token: Refresh token.
        token_type: Always ``Bearer`` (RFC 6750 §4).
        expires_in: Seconds until the access token expires.
        refresh_token_expires_in: Seconds until the refresh token expires
            (JAFAAL extension).
        scope: Space-delimited scopes the access token actually carries.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: StrictStr
    access_token: StrictStr
    refresh_token: StrictStr
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: StrictInt
    refresh_token_expires_in: StrictInt
    scope: StrictStr | None = None


class TokenIntrospectionResponse(BaseModel):
    """RFC 7662 token introspection response.

    ``active`` is the only guaranteed field; the rest are populated only for an
    active token. ``token_use`` and ``sid`` are JAFAAL extensions (§2.2 permits
    them), reporting the token's own use and its session id.

    The extension is named ``token_use`` rather than ``typ`` for the same reason
    the payload claim is: §2.2 already defines ``token_type`` as the RFC 6749
    §7.1 type (``Bearer``), and RFC 9068 uses ``typ`` for the JOSE *header*'s
    media type. A third spelling of "type" meaning a third thing is how a client
    reads the wrong one.

    Attributes:
        active: Whether the token is currently valid.
        sub: Subject (user) identifier.
        scope: Space-delimited granted scopes.
        token_use: JAFAAL token use (``access`` or ``refresh``); mirrors the
            token's own ``token_use`` claim.
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
    token_use: StrictStr | None = None
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
