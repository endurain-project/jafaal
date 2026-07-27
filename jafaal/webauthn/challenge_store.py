"""Short-lived WebAuthn challenge storage, backed by the shared state store.

A WebAuthn ceremony is two round-trips: *begin* mints a random challenge the
authenticator must sign, and *complete* verifies the signature over that exact
challenge. The challenge is held here between the two, with a short TTL, and is
consumed (deleted) on retrieval so it cannot be replayed.

Three namespaces, by ceremony:

* registration — keyed by the authenticated ``user_id``.
* passwordless authentication — keyed by an opaque random ``challenge_id``
  handed to the client (the user is unknown until the assertion is presented).
* second factor — keyed by the pending login's opaque ``mfa_token`` ticket (the
  same secret that addresses the password-verified pending-MFA login).
"""

from __future__ import annotations

import hashlib
import logging
import secrets

import jafaal.settings as jafaal_settings
from jafaal.exceptions import ServiceUnavailableError
from jafaal.orm import UserId
from jafaal.state_store import StateStoreUnavailableError, get_state_store

logger = logging.getLogger(__name__)

_REG_PREFIX = "webauthn:reg"
_AUTH_PREFIX = "webauthn:auth"
_SF_PREFIX = "webauthn:sf"


def new_challenge_id() -> str:
    """Return an unguessable handle identifying a passwordless ceremony."""
    return secrets.token_urlsafe(32)


def _key(namespace: str, discriminator: str) -> str:
    prefix = jafaal_settings.get_settings().store_key_prefix
    return f"{prefix}:{namespace}:{discriminator}"


def _opaque_discriminator(value: str) -> str:
    # Hash the caller-supplied value into a fixed, delimiter-free key segment so
    # it can never collide with or escape the key structure — and, for the
    # second-factor ticket, so the store never holds the ticket itself.
    return hashlib.sha256(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _ttl() -> int:
    return jafaal_settings.get_settings().webauthn.challenge_ttl_seconds


def _store(key: str, challenge: bytes) -> None:
    try:
        get_state_store().set(key, challenge, ttl_seconds=_ttl())
    except StateStoreUnavailableError as err:
        raise ServiceUnavailableError("WebAuthn challenge store is temporarily unavailable.") from err


def _pop(key: str) -> bytes | None:
    try:
        return get_state_store().get_and_delete(key)
    except StateStoreUnavailableError as err:
        raise ServiceUnavailableError("WebAuthn challenge store is temporarily unavailable.") from err


def store_registration_challenge(user_id: UserId, challenge: bytes) -> None:
    """Persist the registration challenge for ``user_id``."""
    _store(_key(_REG_PREFIX, str(user_id)), challenge)


def pop_registration_challenge(user_id: UserId) -> bytes | None:
    """Retrieve and consume the registration challenge for ``user_id``."""
    return _pop(_key(_REG_PREFIX, str(user_id)))


def discard_registration_challenge(user_id: UserId) -> None:
    """Drop any pending registration challenge for ``user_id``.

    Called from the credential-change sweep. ``/register/begin`` is step-up
    gated and ``/register/complete`` is not — the minted challenge *is* the proof
    that step-up passed. So an attacker who holds a stolen access token, passes
    step-up with a password they are about to lose, and stops before completing,
    keeps a live licence to bind a passkey (a full login credential) for the rest
    of the challenge TTL. Rotating the password has to invalidate it.

    Best-effort: a state-store outage is swallowed, because the credential change
    that triggered the sweep must still succeed and the challenge expires on its
    own shortly after.

    Args:
        user_id: The user whose pending registration challenge is dropped.
    """
    try:
        get_state_store().delete(_key(_REG_PREFIX, str(user_id)))
    except StateStoreUnavailableError:
        logger.warning(
            "Could not drop the pending WebAuthn registration challenge; it will expire via TTL",
            exc_info=True,
        )


def store_authentication_challenge(challenge_id: str, challenge: bytes) -> None:
    """Persist a passwordless authentication challenge under ``challenge_id``."""
    _store(_key(_AUTH_PREFIX, challenge_id), challenge)


def pop_authentication_challenge(challenge_id: str) -> bytes | None:
    """Retrieve and consume a passwordless authentication challenge."""
    return _pop(_key(_AUTH_PREFIX, challenge_id))


def store_second_factor_challenge(mfa_token: str, challenge: bytes) -> None:
    """Persist a second-factor challenge for the pending login ``mfa_token``."""
    _store(_key(_SF_PREFIX, _opaque_discriminator(mfa_token)), challenge)


def pop_second_factor_challenge(mfa_token: str) -> bytes | None:
    """Retrieve and consume the second-factor challenge for ``mfa_token``."""
    return _pop(_key(_SF_PREFIX, _opaque_discriminator(mfa_token)))
