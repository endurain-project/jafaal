"""The credential-change revocation sweep.

When an account's password changes — by the user, by an administrator, or
through a reset token — every *other* credential that could still act as that
account has to go with it. Doing that inline at each call site was how two of
them ended up incomplete: the sweep is a list, the list grows every time JAFAAL
gains a credential type, and three copies of a growing list drift.

So the list lives here, once, and every path calls :func:`revoke_derived_credentials`.

What is swept, and why each entry is on the list:

============================  ============================================
Credential                    Why a password change must kill it
============================  ============================================
Sessions                      The refresh token is the long-lived half of a
                              login; leaving one live means the change
                              evicted nobody.
API keys                      ``expires_at`` is optional, so a key minted
                              while an attacker held the account outlives
                              every other credential in this table.
Password-reset tokens         Each is a bearer credential for this account.
                              One phished before the change stays
                              redeemable for the rest of its TTL.
Pending-MFA tickets           An attacker sitting at the second-factor step,
                              having already submitted the old password,
                              would otherwise still complete the login.
Step-up grants                A bearer licence to perform one sensitive
                              operation with no factor at all.
WebAuthn reg. challenges      ``/register/complete`` carries no step-up of
                              its own — the challenge *is* the proof that
                              step-up passed — so a live one is a licence to
                              bind a passkey, which is a full login
                              credential.
============================  ============================================

Deliberately **not** swept:

* **Access tokens.** Stateless and short-lived; they lapse on their own. A
  deployment that needs them dead immediately sets
  :attr:`~jafaal.settings.SessionSettings.strict_binding` (they then die with the
  session) or :attr:`~jafaal.settings.TokenSettings.denylist_enabled`.
* **Registered passkeys and enrolled TOTP.** These are *authenticators*, not
  credentials derived from the password. Silently unenrolling a user's security
  key because they rotated a password would be both surprising and a lockout
  risk; removing one is its own step-up-gated operation.
* **Identity-provider links.** The upstream account is not compromised by a
  local password change, and unlinking would lock an SSO user out of their own
  account.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal.api_keys.crud as jafaal_api_keys_crud
import jafaal.password_reset_tokens.crud as password_reset_tokens_crud
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.webauthn.challenge_store as webauthn_challenge_store
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

__all__ = ["revoke_derived_credentials"]


def revoke_derived_credentials(
    user_id: UserId,
    db: Session,
    *,
    reason: str,
    revoke_sessions: bool = True,
    keep_session_id: str | None = None,
) -> int:
    """Revoke every credential derived from ``user_id``'s password.

    The single implementation of the module docstring's table. Call it from any
    path that invalidates a password; do not re-list its contents at the call
    site.

    The ephemeral-store clears are best-effort by construction (each swallows a
    state-store outage and logs), because the credential change itself must
    still succeed — every one of them is TTL-bounded and expires on its own
    shortly after.

    Args:
        user_id: The account whose derived credentials are revoked.
        db: Active database session. The database writes join the caller's unit
            of work; the caller commits.
        reason: Short machine-readable cause, recorded on the API-key revocation
            (e.g. ``"password_reset"``).
        revoke_sessions: Whether to delete the account's sessions. ``False`` for
            a caller that manages session revocation itself.
        keep_session_id: Session to preserve, so a user changing their own
            password is not logged out of the device they are doing it from.

    Returns:
        The number of sessions revoked (``0`` when ``revoke_sessions`` is off).
    """
    password_reset_tokens_crud.mark_user_password_reset_tokens_used(user_id, db)
    jafaal_api_keys_crud.revoke_all_api_keys_for_user(user_id, db, reason=reason)

    jafaal_security_stores.clear_pending_mfa_for_user(user_id)
    jafaal_security_stores.clear_step_up_reauth_grant(user_id)
    webauthn_challenge_store.discard_registration_challenge(user_id)

    if not revoke_sessions:
        return 0
    revoked = jafaal_sessions_crud.delete_sessions_by_user(
        user_id,
        db,
        exclude_session_id=keep_session_id,
        commit=False,
    )
    logger.info(f"Revoked {revoked} session(s) for user {user_id} ({reason})")
    return revoked
