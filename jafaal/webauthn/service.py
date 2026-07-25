"""WebAuthn (passkey) ceremony orchestration.

Wraps ``py_webauthn`` (the optional ``jafaal[webauthn]`` extra) with JAFAAL's
challenge storage, credential persistence, and user lookup. Three ceremonies:

* **registration** — an authenticated user adds a passkey.
* **passwordless authentication** — an anonymous caller proves possession of a
  registered passkey; the user is resolved from the credential and JAFAAL tokens
  are issued by the caller.
* **second factor** — a password-verified pending login is completed with a
  passkey assertion.

The library is imported defensively so ``import jafaal`` works without the extra;
every entry point calls :func:`_require_webauthn` to fail fast (with an install
hint) when a ceremony is actually invoked.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from sqlalchemy.orm import Session

import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports
import jafaal.settings as jafaal_settings
import jafaal.token_hashing as jafaal_token_hashing
import jafaal.webauthn.challenge_store as challenge_store
import jafaal.webauthn.crud as webauthn_crud
import jafaal.webauthn.models as webauthn_models
from jafaal._core import optional_deps
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

# Optional dependency (``jafaal[webauthn]``). Imported defensively so the package
# imports without it; the accessors fail fast with an install hint when used.
try:
    import webauthn as _webauthn
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers import structs as _structs
    from webauthn.helpers.exceptions import WebAuthnException
except ImportError:  # pragma: no cover - exercised via the missing-dep guard
    _webauthn = None  # type: ignore[assignment]
    _structs = None  # type: ignore[assignment]
    base64url_to_bytes = None  # type: ignore[assignment]
    bytes_to_base64url = None  # type: ignore[assignment]
    WebAuthnException = None  # type: ignore[assignment,misc]

# Errors a verify_* call may raise on an invalid/forged ceremony. ``py_webauthn``
# raises WebAuthnException subclasses; malformed input surfaces as ValueError
# (pydantic parsing). Kept as a tuple so the ``except`` clause is valid whether or
# not the optional dependency is installed.
_VERIFY_ERRORS: tuple[type[BaseException], ...] = (ValueError,)
if WebAuthnException is not None:
    _VERIFY_ERRORS = (WebAuthnException, ValueError)


def _require_webauthn() -> Any:
    """Return the ``webauthn`` module, or fail fast if the extra is missing."""
    return optional_deps.require(
        _webauthn,
        package="webauthn",
        extra="webauthn",
        feature="WebAuthn / passkeys",
    )


# ---------------------------------------------------------------------------
# Config resolution (fail fast on a host misconfiguration)
# ---------------------------------------------------------------------------


def _rp_id() -> str:
    rp_id = jafaal_settings.get_settings().resolved_webauthn_rp_id
    if not rp_id:
        raise jafaal_exceptions.ServiceUnavailableError(
            "WebAuthn is not configured: set AuthSettings.webauthn_rp_id (or base_url)."
        )
    return rp_id


def _origins() -> list[str]:
    origins = jafaal_settings.get_settings().resolved_webauthn_origins
    if not origins:
        raise jafaal_exceptions.ServiceUnavailableError(
            "WebAuthn is not configured: set AuthSettings.webauthn_origins (or base_url)."
        )
    return list(origins)


def _user_verification() -> Any:
    return _structs.UserVerificationRequirement(jafaal_settings.get_settings().webauthn_user_verification)


def _require_user_verification() -> bool:
    return jafaal_settings.get_settings().webauthn_user_verification == "required"


def _passwordless_user_verification() -> Any:
    """User-verification requirement for the passwordless login ceremony.

    Always ``required``: on the passwordless path the passkey is the entire
    authentication, so the authenticator MUST verify the user (PIN/biometric) for
    it to be a genuine two-factor (possession + inherence/knowledge) credential
    rather than mere possession of a synced/exported key. This is enforced
    independent of ``AuthSettings.webauthn_user_verification``, which governs only
    the second-factor path (where the password already provides the first factor).
    """
    return _structs.UserVerificationRequirement.REQUIRED


def _attestation() -> Any:
    return _structs.AttestationConveyancePreference(jafaal_settings.get_settings().webauthn_attestation)


# ---------------------------------------------------------------------------
# Encoding / extraction helpers
# ---------------------------------------------------------------------------


def _options_to_dict(options: Any) -> dict[str, Any]:
    """Serialise ``py_webauthn`` options to the browser-facing JSON object."""
    return json.loads(_webauthn.options_to_json(options))  # type: ignore[union-attr]


def _normalized_credential_id(credential: dict[str, Any]) -> str:
    """Return the assertion's credential id as canonical (unpadded) base64url."""
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str) or not raw:
        raise jafaal_exceptions.InvalidRequestError("Malformed WebAuthn credential: missing id.")
    try:
        return bytes_to_base64url(base64url_to_bytes(raw))  # type: ignore[misc]
    except Exception as err:
        raise jafaal_exceptions.InvalidRequestError("Malformed WebAuthn credential id.") from err


def _extract_transports(credential: dict[str, Any]) -> str | None:
    response = credential.get("response")
    if not isinstance(response, dict):
        return None
    transports = response.get("transports")
    if isinstance(transports, list) and transports:
        cleaned = [str(t) for t in transports if isinstance(t, str)]
        return ",".join(cleaned) or None
    return None


def _descriptors_for_user(user_id: UserId, db: Session) -> list[Any]:
    """Build ``allow_credentials`` descriptors for a user's registered passkeys."""
    descriptors = []
    for cred in webauthn_crud.get_credentials_by_user_id(user_id, db):
        try:
            raw = base64url_to_bytes(cred.credential_id)  # type: ignore[misc]
        except Exception:
            # A stored id we wrote should always decode; skip (don't fail the
            # whole ceremony) if one somehow cannot.
            logger.warning("Skipping unparseable stored credential id (pk=%s)", cred.id, exc_info=True)
        else:
            descriptors.append(_structs.PublicKeyCredentialDescriptor(id=raw))
    return descriptors


# ---------------------------------------------------------------------------
# Registration ceremony (authenticated user)
# ---------------------------------------------------------------------------


def _user_handle(user: jafaal_ports.UserProtocol) -> bytes:
    """Return a stable, opaque WebAuthn user handle for ``user``.

    The user handle is stored by the authenticator and returned verbatim in
    assertions (notably for discoverable/resident credentials), so it must not
    carry personally identifying information and should not be a guessable or
    cross-site-correlatable value. Using the raw ``user.id`` would leak the
    application's internal (often sequential) identifier to every authenticator.

    Instead derive an opaque 32-byte handle as a keyed HMAC of the user id under
    a dedicated subkey of the server secret: it is stable per user (so every
    passkey a user registers shares one account handle, as WebAuthn requires),
    non-identifying, and not derivable or correlatable without
    ``AuthSettings.secret_key``. Authentication resolves the user from the
    presented credential id, never from this handle, so the derivation only needs
    to be deterministic - never reversible.
    """
    return bytes.fromhex(
        jafaal_token_hashing.hmac_sha256(str(user.id), jafaal_token_hashing.KeyPurpose.WEBAUTHN_USER_HANDLE)
    )


def begin_registration(user: jafaal_ports.UserProtocol, db: Session) -> dict[str, Any]:
    """Generate registration options and store the challenge for ``user``."""
    _require_webauthn()
    settings = jafaal_settings.get_settings()

    exclude = _descriptors_for_user(user.id, db)
    selection = _structs.AuthenticatorSelectionCriteria(
        resident_key=_structs.ResidentKeyRequirement.PREFERRED,
        user_verification=_user_verification(),
    )
    options = _webauthn.generate_registration_options(  # type: ignore[union-attr]
        rp_id=_rp_id(),
        rp_name=settings.resolved_webauthn_rp_name,
        user_name=user.username,
        user_id=_user_handle(user),
        user_display_name=user.username,
        attestation=_attestation(),
        authenticator_selection=selection,
        exclude_credentials=exclude,
    )
    challenge_store.store_registration_challenge(user.id, options.challenge)
    return _options_to_dict(options)


def complete_registration(
    user: jafaal_ports.UserProtocol,
    credential: dict[str, Any],
    label: str | None,
    db: Session,
) -> webauthn_models.WebAuthnCredential:
    """Verify a registration response and persist the new passkey for ``user``."""
    _require_webauthn()

    challenge = challenge_store.pop_registration_challenge(user.id)
    if challenge is None:
        raise jafaal_exceptions.InvalidRequestError(
            "No pending WebAuthn registration challenge (it may have expired). Start registration again."
        )

    try:
        verification = _webauthn.verify_registration_response(  # type: ignore[union-attr]
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origins(),
            require_user_verification=_require_user_verification(),
        )
    except _VERIFY_ERRORS as err:
        logger.warning("WebAuthn registration verification failed: %s", err)
        raise jafaal_exceptions.InvalidRequestError("WebAuthn registration verification failed.") from err

    credential_id_b64 = bytes_to_base64url(verification.credential_id)  # type: ignore[misc]
    if webauthn_crud.get_credential_by_credential_id(credential_id_b64, db) is not None:
        raise jafaal_exceptions.ConflictError("This passkey is already registered.")

    device_type = getattr(verification.credential_device_type, "value", verification.credential_device_type)
    return webauthn_crud.create_credential(
        user_id=user.id,
        credential_id=credential_id_b64,
        public_key=base64.b64encode(verification.credential_public_key).decode("ascii"),
        sign_count=verification.sign_count,
        transports=_extract_transports(credential),
        aaguid=verification.aaguid,
        label=label,
        backup_eligible=(device_type == "multi_device"),
        backup_state=bool(verification.credential_backed_up),
        db=db,
    )


# ---------------------------------------------------------------------------
# Passwordless authentication ceremony (anonymous)
# ---------------------------------------------------------------------------


def begin_authentication(username: str | None, db: Session) -> tuple[str, dict[str, Any]]:
    """Generate authentication options and store the challenge under a handle.

    When ``username`` is given the options are scoped to that user's passkeys;
    when it is omitted (or unknown) an empty allow-list yields a usernameless
    (discoverable-credential) ceremony. An unknown username is treated like the
    usernameless case so the endpoint never discloses whether an account exists.
    """
    _require_webauthn()

    allow_credentials: list[Any] = []
    if username:
        user = jafaal_ports.get_user_repository().get_by_username(username, db)
        if user is not None:
            allow_credentials = _descriptors_for_user(user.id, db)

    options = _webauthn.generate_authentication_options(  # type: ignore[union-attr]
        rp_id=_rp_id(),
        allow_credentials=allow_credentials or None,
        user_verification=_passwordless_user_verification(),
    )
    challenge_id = challenge_store.new_challenge_id()
    challenge_store.store_authentication_challenge(challenge_id, options.challenge)
    return challenge_id, _options_to_dict(options)


def _verify_assertion(
    stored: webauthn_models.WebAuthnCredential,
    credential: dict[str, Any],
    challenge: bytes,
    *,
    require_user_verification: bool,
) -> Any:
    try:
        return _webauthn.verify_authentication_response(  # type: ignore[union-attr]
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origins(),
            credential_public_key=base64.b64decode(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=require_user_verification,
        )
    except _VERIFY_ERRORS as err:
        logger.warning("WebAuthn authentication verification failed: %s", err)
        raise jafaal_exceptions.InvalidCredentialsError("WebAuthn authentication failed.") from err


def complete_authentication(
    challenge_id: str,
    credential: dict[str, Any],
    db: Session,
) -> jafaal_ports.UserProtocol:
    """Verify a passwordless assertion and return the authenticated user."""
    _require_webauthn()

    challenge = challenge_store.pop_authentication_challenge(challenge_id)
    if challenge is None:
        raise jafaal_exceptions.InvalidCredentialsError(
            "No pending WebAuthn authentication challenge (it may have expired)."
        )

    credential_id_b64 = _normalized_credential_id(credential)
    stored = webauthn_crud.get_credential_by_credential_id(credential_id_b64, db)
    if stored is None:
        raise jafaal_exceptions.InvalidCredentialsError("WebAuthn authentication failed.")

    verification = _verify_assertion(stored, credential, challenge, require_user_verification=True)
    webauthn_crud.update_sign_count(stored, verification.new_sign_count, db)

    user = jafaal_ports.get_user_repository().get_by_id(stored.user_id, db)
    if user is None:
        raise jafaal_exceptions.InvalidCredentialsError("WebAuthn authentication failed.")
    return user


# ---------------------------------------------------------------------------
# Second-factor ceremony (password-verified pending login)
# ---------------------------------------------------------------------------


def begin_second_factor(mfa_token: str, user_id: UserId | None, db: Session) -> dict[str, Any]:
    """Generate second-factor options for a pending login and store the challenge.

    The challenge is keyed by the opaque ``mfa_token`` ticket that addresses the
    pending-MFA login. When ``user_id`` is ``None`` (the ticket does not address
    a live pending login) an empty allow-list is used so the endpoint does not
    disclose whether a login is pending or which passkeys the account holds; the
    ceremony simply cannot be completed.
    """
    _require_webauthn()

    allow_credentials = _descriptors_for_user(user_id, db) if user_id is not None else []
    options = _webauthn.generate_authentication_options(  # type: ignore[union-attr]
        rp_id=_rp_id(),
        allow_credentials=allow_credentials or None,
        user_verification=_user_verification(),
    )
    challenge_store.store_second_factor_challenge(mfa_token, options.challenge)
    return _options_to_dict(options)


def complete_second_factor(
    user_id: UserId,
    credential: dict[str, Any],
    challenge: bytes,
    db: Session,
) -> bool:
    """Verify a second-factor assertion belonging to ``user_id``.

    Returns ``True`` on success; the credential must belong to ``user_id`` (the
    pending login's user) so one user's passkey cannot satisfy another's second
    factor.
    """
    _require_webauthn()

    credential_id_b64 = _normalized_credential_id(credential)
    stored = webauthn_crud.get_credential_by_credential_id(credential_id_b64, db)
    if stored is None or stored.user_id != user_id:
        return False

    verification = _verify_assertion(
        stored, credential, challenge, require_user_verification=_require_user_verification()
    )
    webauthn_crud.update_sign_count(stored, verification.new_sign_count, db)
    return True
