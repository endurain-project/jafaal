"""Request/response schemas for the WebAuthn (passkey) ceremonies.

The ``options`` payloads returned by the *begin* endpoints are the JSON objects
the browser's ``navigator.credentials.create()`` /
``navigator.credentials.get()`` expect (produced by ``webauthn.options_to_json``
and parsed back to a ``dict``). The ``credential`` payloads posted to the
*complete* endpoints are the authenticator responses those browser calls return,
passed through to ``py_webauthn`` for verification.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from jafaal.orm import UserId


class WebAuthnRegistrationComplete(BaseModel):
    """Payload finishing a registration ceremony.

    Attributes:
        credential: The authenticator attestation response from
            ``navigator.credentials.create()``.
        label: Optional user-friendly name for the new credential.
    """

    credential: dict[str, Any] = Field(..., description="Authenticator attestation response")
    label: StrictStr | None = Field(
        default=None,
        max_length=255,
        description="Optional user-friendly credential name",
    )


class WebAuthnAuthenticationBegin(BaseModel):
    """Payload starting a passwordless authentication ceremony.

    Attributes:
        username: Optional login handle. Omit for a usernameless
            (discoverable-credential) flow, where the authenticator selects the
            credential and the user is resolved from it at completion.
    """

    username: StrictStr | None = Field(
        default=None,
        max_length=250,
        description="Login handle (omit for usernameless/discoverable login)",
    )


class WebAuthnAuthenticationBeginResponse(BaseModel):
    """Options plus the opaque challenge handle returned by *authenticate/begin*.

    Attributes:
        challenge_id: Opaque handle binding this ceremony to its stored
            challenge; echo it back to *authenticate/complete*.
        options: The ``navigator.credentials.get()`` request options.
    """

    challenge_id: StrictStr = Field(..., description="Opaque challenge handle")
    options: dict[str, Any] = Field(..., description="Credential request options")


class WebAuthnAuthenticationComplete(BaseModel):
    """Payload finishing a passwordless authentication ceremony.

    Attributes:
        challenge_id: The handle returned by *authenticate/begin*.
        credential: The authenticator assertion response from
            ``navigator.credentials.get()``.
        client_id: The registered client the tokens are issued to. Its
            registration decides delivery mode and scope ceiling.
    """

    challenge_id: StrictStr = Field(..., description="Opaque challenge handle from begin")
    credential: dict[str, Any] = Field(..., description="Authenticator assertion response")
    client_id: StrictStr = Field(..., max_length=256, description="Registered client receiving the tokens")


class WebAuthnSecondFactorBegin(BaseModel):
    """Payload starting a WebAuthn second-factor ceremony after password login.

    Attributes:
        mfa_token: The opaque ticket returned by ``/auth/login``, proving this
            caller satisfied the password factor.
    """

    mfa_token: StrictStr = Field(..., max_length=512, description="Pending-login ticket from /auth/login")


class WebAuthnSecondFactorComplete(BaseModel):
    """Payload finishing a WebAuthn second-factor ceremony.

    Attributes:
        mfa_token: The opaque ticket returned by ``/auth/login``.
        credential: The authenticator assertion response.
        client_id: The registered client the tokens are issued to.
    """

    mfa_token: StrictStr = Field(..., max_length=512, description="Pending-login ticket from /auth/login")
    credential: dict[str, Any] = Field(..., description="Authenticator assertion response")
    client_id: StrictStr = Field(..., max_length=256, description="Registered client receiving the tokens")


class WebAuthnCredentialRead(BaseModel):
    """A registered passkey, safe to return to its owner.

    Attributes:
        id: Surrogate primary key (used to delete the credential).
        user_id: Owner's user id.
        label: User-friendly credential name.
        transports: Comma-joined transport hints.
        aaguid: Authenticator model identifier.
        backup_eligible: Whether the credential can be backed up/synced.
        backup_state: Whether the credential is currently backed up/synced.
        created_at: Registration timestamp.
        last_used_at: Last successful authentication timestamp.
    """

    id: int = Field(..., description="Surrogate primary key")
    user_id: UserId = Field(..., description="Owner's user id")
    label: StrictStr | None = Field(None, description="User-friendly credential name")
    transports: StrictStr | None = Field(None, description="Comma-joined transport hints")
    aaguid: StrictStr | None = Field(None, description="Authenticator model identifier")
    backup_eligible: bool | None = Field(None, description="Whether the credential can be backed up")
    backup_state: bool | None = Field(None, description="Whether the credential is currently backed up")
    created_at: datetime = Field(..., description="Registration timestamp")
    last_used_at: datetime | None = Field(None, description="Last successful authentication timestamp")

    model_config = ConfigDict(from_attributes=True)
