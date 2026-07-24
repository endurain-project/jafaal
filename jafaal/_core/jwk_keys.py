"""Asymmetric JWK helpers for JWT signing, verification, and JWKS publication.

Low-level utilities over ``joserfc`` shared by the token manager (signing /
verification) and the settings layer (validation): import PEM key material, pin
the RFC 7638 thumbprint as the ``kid``, and render public JSON Web Keys. Kept in
``_core`` so both layers use one implementation.

Only asymmetric RSA/EC algorithms are supported here. ``EdDSA`` is intentionally
excluded: ``joserfc`` marks the ``EdDSA`` JOSE identifier as deprecated (per
RFC 9864) and emits a ``SecurityWarning`` on use, so it is not offered until that
stabilises.
"""

from __future__ import annotations

from typing import Any

from joserfc.jwk import ECKey, RSAKey

#: RSA-family JWT signing algorithms (PKCS#1 v1.5 and PSS).
RSA_ALGORITHMS: frozenset[str] = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
#: Elliptic-curve JWT signing algorithms.
EC_ALGORITHMS: frozenset[str] = frozenset({"ES256", "ES384", "ES512"})
#: Every asymmetric algorithm JAFAAL can sign/verify with.
ASYMMETRIC_ALGORITHMS: frozenset[str] = RSA_ALGORITHMS | EC_ALGORITHMS

AsymmetricKey = RSAKey | ECKey


def _key_class(algorithm: str) -> type[RSAKey] | type[ECKey]:
    """Return the ``joserfc`` key class for an asymmetric algorithm."""
    if algorithm in RSA_ALGORITHMS:
        return RSAKey
    if algorithm in EC_ALGORITHMS:
        return ECKey
    raise ValueError(f"{algorithm!r} is not a supported asymmetric JWT algorithm")


def import_private_signing_key(pem: str, algorithm: str) -> AsymmetricKey:
    """Import and validate the PEM private key used to sign JWTs.

    Args:
        pem: PEM-encoded private key.
        algorithm: The asymmetric algorithm it must match (RSA vs EC family).

    Returns:
        The imported private key.

    Raises:
        ValueError: If the PEM is malformed, is the wrong key type for the
            algorithm, or is a public (not private) key.
    """
    cls = _key_class(algorithm)
    try:
        key = cls.import_key(pem)
    except Exception as err:  # normalise any joserfc/cryptography import failure
        raise ValueError(f"not a valid {algorithm} private key ({type(err).__name__})") from err
    if not key.is_private:
        raise ValueError(f"a {algorithm} signing key must be a private key, got a public key")
    return key


def import_verification_key(pem: str, algorithm: str) -> AsymmetricKey:
    """Import a public verification key (from a private *or* public PEM).

    The returned key carries its RFC 7638 thumbprint as ``kid`` so a
    ``KeySet`` can resolve it by the token header's ``kid``.

    Raises:
        ValueError: If the PEM is malformed or the wrong key type.
    """
    cls = _key_class(algorithm)
    try:
        key = cls.import_key(pem)
    except Exception as err:
        raise ValueError(f"not a valid {algorithm} key ({type(err).__name__})") from err
    return public_verification_key(key, algorithm)


def public_verification_key(key: AsymmetricKey, algorithm: str) -> AsymmetricKey:
    """Return the public half of ``key`` with its thumbprint pinned as ``kid``."""
    cls = _key_class(algorithm)
    public: dict[str, Any] = key.as_dict(private=False)
    public["kid"] = key.thumbprint()
    return cls.import_key(public)


def jwk_entry(key: AsymmetricKey, algorithm: str) -> dict[str, Any]:
    """Return a public JWK dict for ``key`` tagged for signature verification."""
    entry: dict[str, Any] = key.as_dict(private=False)
    entry["kid"] = key.thumbprint()
    entry["use"] = "sig"
    entry["alg"] = algorithm
    return entry
