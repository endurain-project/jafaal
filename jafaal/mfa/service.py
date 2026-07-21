"""Auth-owned MFA primitives and per-user MFA workflow helpers.

Module layering (where MFA logic lives):

- ``jafaal.mfa.service`` (this module): pure TOTP/QR helpers
  (:func:`generate_totp_secret`, :func:`verify_totp`,
  :func:`generate_qr_code`) and the per-user workflow helpers that read/write
  MFA state (:func:`setup_user_mfa`, :func:`enable_user_mfa`,
  :func:`disable_user_mfa`, :func:`verify_user_mfa`,
  :func:`is_mfa_enabled_for_user`). No HTTP request/response shapes here.
- ``jafaal.mfa.crud``: persistence for the ``users_mfa`` table.
- ``jafaal._internal.services.mfa_workflow``: route-facing orchestration (step-up
  verification, setup-secret store handling, response/schema shaping) that
  composes the helpers in this module. Profile routes call that module, not
  this one, for end-to-end flows.
"""

from __future__ import annotations

import base64
import hmac
import logging
import time
from io import BytesIO
from typing import TYPE_CHECKING

import pyotp
import qrcode
from sqlalchemy.orm import Session

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.mfa.backup_codes.crud as mfa_backup_codes_crud
import jafaal.mfa.backup_codes.utils as mfa_backup_codes_utils
import jafaal.mfa.crud as jafaal_mfa_crud
import jafaal.mfa.schema as mfa_schema
import jafaal.settings as jafaal_settings
from jafaal._core import crypto
from jafaal.orm import UserId
from jafaal.state_store import StateStoreUnavailableError, get_state_store

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import jafaal.identity_service as jafaal_identity_service

# ---------------------------------------------------------------------------
# TOTP / QR-code helpers (pure, no DB)
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """
    Generate random TOTP secret for MFA.

    Returns:
        Base32-encoded secret string.
    """
    return pyotp.random_base32()


def verify_totp(secret: str, token: str) -> bool:
    """
    Verify TOTP token against secret.

    Args:
        secret: Base32-encoded TOTP secret.
        token: TOTP token to verify.

    Returns:
        True if token is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)  # Allow 1 window tolerance


# TOTP replay protection --------------------------------------------------- #
# A valid TOTP code stays valid for the whole ``valid_window`` tolerance
# (±1 step ≈ 90s). Without single-use enforcement the same code can be
# replayed within that window (e.g. on the step-up path, which is not bounded
# by the single-use pending-MFA claim the login flow has). We record the
# matched timestep in the ephemeral state store and reject any second use.
_TOTP_VALID_WINDOW = 1
# Retain the marker a little beyond the acceptance window so a code cannot be
# replayed while still valid, then let it expire (no unbounded growth).
_TOTP_REPLAY_TTL_SECONDS = 30 * (2 * _TOTP_VALID_WINDOW + 1) + 30


def _matched_totp_timestep(secret: str, token: str, valid_window: int = _TOTP_VALID_WINDOW) -> int | None:
    """Return the absolute TOTP timestep ``token`` matches, or ``None``.

    Mirrors :func:`verify_totp` (same ``valid_window`` tolerance) but returns
    the matched counter so the caller can enforce single-use per timestep.
    Comparison is constant-time.

    Args:
        secret: Base32-encoded TOTP secret.
        token: Candidate TOTP code.
        valid_window: Number of steps of clock-drift tolerance either side.

    Returns:
        The matched timestep (``unix_time // interval``), or ``None`` if the
        code does not match any step in the window.
    """
    totp = pyotp.TOTP(secret)
    current_timestep = int(time.time()) // totp.interval
    for offset in range(-valid_window, valid_window + 1):
        candidate = current_timestep + offset
        if hmac.compare_digest(totp.at(candidate * totp.interval), token):
            return candidate
    return None


def _totp_used_key(user_id: UserId, timestep: int) -> str:
    """Build the state-store key marking a consumed TOTP timestep for a user."""
    prefix = jafaal_settings.get_settings().store_key_prefix
    return f"{prefix}:mfa:totp_used:{user_id}:{timestep}"


def _totp_timestep_already_used(user_id: UserId, timestep: int) -> bool:
    """Return ``True`` if this TOTP timestep was already consumed (a replay).

    Fails open on a state-store outage: replay protection is defense-in-depth
    layered on top of the (unchanged) TOTP verification, so an unavailable
    backend must not lock users out of MFA entirely.
    """
    try:
        return get_state_store().get(_totp_used_key(user_id, timestep)) is not None
    except StateStoreUnavailableError as err:
        logger.warning("TOTP replay check skipped; state store unavailable", exc_info=err)
        return False


def _mark_totp_timestep_used(user_id: UserId, timestep: int) -> None:
    """Record that ``timestep`` has been consumed for ``user_id`` (with TTL)."""
    try:
        get_state_store().set(
            _totp_used_key(user_id, timestep),
            b"1",
            ttl_seconds=_TOTP_REPLAY_TTL_SECONDS,
        )
    except StateStoreUnavailableError as err:
        logger.warning("Could not record consumed TOTP timestep; replay protection degraded", exc_info=err)


def generate_qr_code(secret: str, username: str, app_name: str = "Jafaal") -> str:
    """
    Generate QR code for MFA setup.

    Args:
        secret: TOTP secret.
        username: User's username.
        app_name: Application name for MFA.

    Returns:
        Base64-encoded PNG QR code as data URI.
    """
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name=app_name)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_base64}"


# ---------------------------------------------------------------------------
# MFA workflow functions
# ---------------------------------------------------------------------------


def setup_user_mfa(user_id: UserId, db: Session) -> mfa_schema.MFASetupResponse:
    """
    Setup MFA for user.

    Args:
        user_id: User ID to setup MFA for.
        db: Database session.

    Returns:
        MFA setup response with secret and QR code.

    Raises:
        NotFoundError: If the user is not found.
        InvalidRequestError: If MFA is already enabled.
    """
    user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)

    if user.mfa_enabled:
        raise jafaal_exceptions.InvalidRequestError("MFA is already enabled for this user")

    secret = generate_totp_secret()
    app_name = jafaal_settings.get_settings().app_name
    qr_code = generate_qr_code(secret, user.username, app_name)

    return mfa_schema.MFASetupResponse(secret=secret, qr_code=qr_code, app_name=app_name)


def enable_user_mfa(
    user_id: UserId,
    secret: str,
    mfa_code: str,
    identity_service: jafaal_identity_service.IdentityService,
    db: Session,
) -> list[str]:
    """
    Enable MFA for user after verification.

    Args:
        user_id: User ID to enable MFA for.
        secret: TOTP secret to verify.
        mfa_code: MFA code to verify.
        identity_service: Identity service dependency.
        db: Database session.

    Returns:
        List of generated backup codes.

    Raises:
        NotFoundError: If the user is not found.
        InvalidRequestError: If MFA is already enabled.
        InvalidMFACodeError: If the verification code is invalid.
        InternalError: If encryption of the MFA secret fails.
    """
    user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)

    if user.mfa_enabled:
        raise jafaal_exceptions.InvalidRequestError("MFA is already enabled for this user")

    if not verify_totp(secret, mfa_code):
        raise jafaal_exceptions.InvalidMFACodeError()

    encrypted_secret = crypto.encrypt_token_fernet(secret)

    if not encrypted_secret:
        raise jafaal_exceptions.InternalError("Failed to encrypt MFA secret")

    jafaal_mfa_crud.update_user_mfa(user_id, db, encrypted_secret=encrypted_secret)

    backup_codes = mfa_backup_codes_crud.create_backup_codes(user_id, identity_service, db)

    return backup_codes


def disable_user_mfa(user_id: UserId, db: Session) -> None:
    """
    Clear MFA state for user.

    This helper does NOT verify any MFA code itself — callers
    are responsible for proving identity (e.g. via
    :func:`jafaal._internal.services.step_up_service.verify_step_up_credentials`,
    which accepts both TOTP and backup codes for parity with login).
    Performing the check here as well would either double-charge
    a backup code or, worse, reject a backup code that step-up
    just accepted.

    Args:
        user_id: User ID to disable MFA for.
        db: Database session.

    Raises:
        NotFoundError: If the user is not found.
        InvalidRequestError: If MFA is not currently enabled.
    """
    user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)

    if not user.mfa_enabled:
        raise jafaal_exceptions.InvalidRequestError("MFA is not enabled for this user")

    jafaal_mfa_crud.update_user_mfa(user_id, db)
    mfa_backup_codes_crud.delete_user_backup_codes(user_id, db)


def verify_user_mfa(
    user_id: UserId,
    mfa_code: str,
    identity_service: jafaal_identity_service.IdentityService,
    db: Session,
) -> bool:
    """
    Verify MFA code for user (TOTP or backup code).

    Args:
        user_id: User ID to verify MFA for.
        mfa_code: MFA code to verify (6-digit TOTP or 8-character backup code).
        identity_service: Identity service dependency.
        db: Database session.

    Returns:
        True if code is valid, False otherwise.

    Raises:
        NotFoundError: If the user is not found.

    Notes:
        - First tries TOTP verification (6 digits)
        - If TOTP fails and code is 9 characters (XXXX-XXXX), tries backup code
        - Backup codes are consumed on successful verification
    """
    user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)

    mfa_row = jafaal_mfa_crud.get_user_mfa_row(user.id, db)
    if not mfa_row or not mfa_row.mfa_enabled or not mfa_row.mfa_secret:
        return False

    # Normalize code (remove whitespaces in the beginning and end, uppercase)
    normalized_code = mfa_code.strip().upper()

    # Try TOTP first (6 digits)
    if len(normalized_code) == 6 and normalized_code.isdigit():
        try:
            secret = crypto.decrypt_token_fernet(mfa_row.mfa_secret)
            if not secret:
                logger.error("Failed to decrypt MFA secret")
                return False

            # Resolve which timestep the code matches so we can enforce
            # single-use (replay protection) rather than accepting the same
            # code repeatedly while it stays inside the validity window.
            matched_timestep = _matched_totp_timestep(secret, normalized_code)
            if matched_timestep is not None:
                if _totp_timestep_already_used(user.id, matched_timestep):
                    logger.warning(f"Rejected replayed TOTP code for user {user_id}")
                    return False
                _mark_totp_timestep_used(user.id, matched_timestep)
                logger.debug(f"User {user_id} verified MFA with TOTP")
                return True
        except ValueError as err:
            # Covers binascii.Error (non-base32 secret) and any other value
            # error from the pyotp stack; treat as verification failure.
            logger.error(f"Error in TOTP verification: {err}", exc_info=err)
            return False
        # Unexpected errors (I/O, crypto infrastructure failures, etc.) are
        # intentionally left unhandled so they surface to the global handler
        # rather than being silently swallowed as a False return.

    # Try backup code (9 alphanumeric characters with dash XXXX-XXXX)
    elif (
        len(normalized_code) == 9
        and normalized_code[4] == "-"
        and mfa_backup_codes_utils.verify_and_consume_backup_code(
            user_id,
            normalized_code,
            identity_service,
            db,
        )
    ):
        return True

    # Invalid format or code didn't match
    return False


def is_mfa_enabled_for_user(user_id: UserId, db: Session) -> bool:
    """
    Check if MFA is enabled for user.

    Args:
        user_id: User ID to check.
        db: Database session.

    Returns:
        True if MFA is enabled, False otherwise.
    """
    try:
        user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
    except jafaal_exceptions.NotFoundError:
        return False

    if not user:
        return False
    mfa_row = jafaal_mfa_crud.get_user_mfa_row(user.id, db)
    return bool(mfa_row and mfa_row.mfa_enabled and mfa_row.mfa_secret is not None)
