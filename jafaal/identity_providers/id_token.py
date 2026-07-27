"""OIDC ID-token verification primitives.

The pure, stateless half of "is this ID token genuine?" — algorithm pinning, JWKS
key selection, signature decoding, and the two binding checks OIDC Core requires
(``at_hash`` and the userinfo ``sub`` cross-check).

Kept apart from :mod:`jafaal.identity_providers.service` because none of it needs
a database, an HTTP client, or a cache: it is a function of the token and the key
set. That makes it directly testable, and it keeps the cryptographic decisions —
which are the ones worth reviewing closely — in one file rather than scattered
through several hundred lines of flow orchestration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from typing import Any

from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.jwk import ECKey, RSAKey

import jafaal.exceptions as jafaal_exceptions

logger = logging.getLogger(__name__)

__all__ = [
    "ID_TOKEN_ALLOWED_ALGORITHMS",
    "assert_userinfo_subject_matches",
    "decode_with_any_key",
    "select_jwks_keys",
    "verify_at_hash",
]

# Allow-list of acceptable ID-token signature algorithms.
#
# OIDC ID tokens are verified against the IdP's *public* JWKS keys, so only
# asymmetric algorithms are valid. Pinning this list (and passing it to
# ``jwt.decode``) is mandatory defense-in-depth: without it the verifier would
# trust whatever ``alg`` the token header advertises. That would re-open two
# classic attacks — ``alg=none`` (no signature) and RS256→HS256 confusion
# (an attacker signs an HS256 token using the well-known RSA public key bytes
# as the HMAC secret). Symmetric ``HS*`` algorithms are intentionally excluded
# so a JWKS that publishes an ``oct`` key cannot be abused for key confusion.
ID_TOKEN_ALLOWED_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

# Hash function used to compute ``at_hash`` for each signing algorithm (OIDC
# Core 1.0 §3.1.3.6: the hash is the one used by the token's ``alg``). EdDSA in
# OIDC uses Ed25519, whose hash is SHA-512.
_AT_HASH_HASH_BY_ALG: dict[str, str] = {
    "RS256": "sha256",
    "ES256": "sha256",
    "PS256": "sha256",
    "RS384": "sha384",
    "ES384": "sha384",
    "PS384": "sha384",
    "RS512": "sha512",
    "ES512": "sha512",
    "PS512": "sha512",
    "EdDSA": "sha512",
}


def verify_at_hash(access_token: str, alg: str, at_hash_claim: str) -> None:
    """Verify an ID token ``at_hash`` against the issued access token.

    ``at_hash`` is the base64url-encoded left-most half of the hash of the ASCII
    access-token octets, using the hash of the token's signature ``alg``
    (OIDC Core 1.0 §3.1.3.6). Validating it binds the ID token to the access
    token, detecting a swapped/mismatched access token.

    Args:
        access_token: The access token returned alongside the ID token.
        alg: The ID token's signature algorithm (already allow-listed).
        at_hash_claim: The ``at_hash`` claim value from the ID token.

    Raises:
        InvalidTokenError: If the computed hash does not match ``at_hash_claim``.
    """
    hash_name = _AT_HASH_HASH_BY_ALG.get(alg)
    if hash_name is None:
        # Signature is already verified; skip if we cannot map the alg to a hash.
        logger.debug(f"Skipping at_hash validation for unmapped algorithm {alg}")
        return
    digest = hashlib.new(hash_name, access_token.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected, at_hash_claim):
        logger.warning("ID token at_hash does not match the issued access token")
        raise jafaal_exceptions.InvalidTokenError("ID token at_hash mismatch")


def _import_jwks_key(key_data: dict[str, Any]) -> RSAKey | ECKey | None:
    """Import one JWKS entry, or return ``None`` when it is unusable.

    A JWK Set may legitimately mix key types and include entries for other uses
    (e.g. encryption), so an entry we cannot import is skipped rather than
    failing the whole verification.

    **Only asymmetric keys are materialised.** An ID token is verified against
    the provider's *public* key, so a symmetric ``oct`` entry can never be the
    right answer — and importing one would leave a live RS256→HS256 confusion
    primitive sitting in the candidate list, where its harmlessness depends
    entirely on :data:`ID_TOKEN_ALLOWED_ALGORITHMS` continuing to exclude every
    ``HS*``. Refusing the key type here means that safety property is enforced
    twice, independently, rather than resting on one distant constant.

    Args:
        key_data: A single JWK from the provider's key set.

    Returns:
        The imported key, or ``None`` if the type is unsupported or malformed.
    """
    key_type = key_data.get("kty")
    try:
        if key_type == "RSA":
            return RSAKey.import_key(key_data)
        if key_type == "EC":
            return ECKey.import_key(key_data)
    except Exception:
        logger.warning(f"Skipping unimportable JWKS entry (kty={key_type}, kid={key_data.get('kid')})")
        return None
    if key_type == "oct":
        logger.warning(
            f"Skipping symmetric JWKS entry (kid={key_data.get('kid')}): an ID token is verified against a "
            "public key, so a shared secret is never a valid candidate."
        )
        return None
    logger.debug(f"Skipping JWKS entry with unsupported key type: {key_type}")
    return None


def select_jwks_keys(jwks: dict[str, Any], kid: str | None) -> list[RSAKey | ECKey]:
    """Return the JWKS keys to try for an ID token, most likely first.

    When the token carries a ``kid`` that matches an entry, only that key is
    used. Otherwise every usable key in the set is returned: ``kid`` is optional
    on an ID token (OIDC Core does not require it, and single-key providers
    routinely omit it), so demanding one would refuse those providers outright.
    Trying the whole set is not a weakening — the signature must still verify
    against a key the IdP itself published, under the pinned algorithm
    allow-list.

    Args:
        jwks: The provider's JSON Web Key Set.
        kid: The ``kid`` from the ID token header, if any.

    Returns:
        Candidate keys; empty when the set holds nothing usable.
    """
    entries = [entry for entry in jwks.get("keys", []) if isinstance(entry, dict)]
    if kid:
        matched = [entry for entry in entries if entry.get("kid") == kid]
        if matched:
            entries = matched
        else:
            logger.warning(f"No JWKS entry matches kid={kid}; trying every published key")
    # Signing keys only: an entry explicitly marked for encryption can never
    # have produced this signature.
    entries = [entry for entry in entries if entry.get("use") in (None, "sig")]
    return [key for key in (_import_jwks_key(entry) for entry in entries) if key is not None]


def decode_with_any_key(id_token: str, keys: list[RSAKey | ECKey]) -> Any:
    """Decode ``id_token`` against the first key whose signature verifies.

    Args:
        id_token: The raw ID token JWT.
        keys: Candidate verification keys from the provider's JWKS.

    Returns:
        The decoded token.

    Raises:
        BadSignatureError: If no candidate key verifies the signature.
    """
    last_error: Exception | None = None
    for key in keys:
        try:
            return jwt.decode(id_token, key, algorithms=list(ID_TOKEN_ALLOWED_ALGORITHMS))
        except BadSignatureError as err:
            last_error = err
            continue
    raise last_error if last_error is not None else BadSignatureError()


def assert_userinfo_subject_matches(
    userinfo_claims: dict[str, Any],
    id_token_claims: dict[str, Any],
) -> None:
    """Assert the userinfo response describes the ID token's subject.

    OIDC Core 1.0 §5.3.2: *"The sub Claim in the UserInfo Response MUST be
    verified to exactly match the sub Claim in the ID Token; if they do not
    match, the UserInfo Response values MUST NOT be used."*

    Merely letting the ID token's ``sub`` win a dict merge is not enough: the
    remaining userinfo claims — above all ``email`` and ``email_verified`` —
    would still be carried into user provisioning, where a verified email links
    the session to an *existing* local account. A userinfo endpoint that is
    compromised, confused (an IdP mix-up), or simply buggy could therefore graft
    a victim's email onto an attacker's subject.

    Args:
        userinfo_claims: The raw userinfo-endpoint response.
        id_token_claims: The claims of the already-verified ID token.

    Raises:
        InvalidTokenError: If the userinfo response carries no ``sub``, or one
            that differs from the ID token's.
    """
    id_token_subject = id_token_claims.get("sub")
    userinfo_subject = userinfo_claims.get("sub")
    if not isinstance(userinfo_subject, str) or not userinfo_subject:
        logger.warning("Userinfo response carries no 'sub' claim; refusing to merge it with the ID token")
        raise jafaal_exceptions.InvalidTokenError("Userinfo response is missing the 'sub' claim")
    if not isinstance(id_token_subject, str) or not hmac.compare_digest(userinfo_subject, id_token_subject):
        logger.warning("Userinfo 'sub' does not match the ID token 'sub'; refusing to use the userinfo response")
        raise jafaal_exceptions.InvalidTokenError("Userinfo subject does not match the ID token subject")
