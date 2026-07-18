"""Dependency-free hashing primitives shared across layers.

Holds the lowest-level hash helper used for deriving stable lookup keys
(e.g. hashed usernames, user ids, and token keys). Keeping the primitive
here — with no imports from other JAFAAL packages — lets every layer depend
on it downward without risking an import cycle.
"""

import hashlib


def sha256_hex(value: str) -> str:
    """Return the SHA-256 hex digest of ``value``.

    Args:
        value: The string to hash. Callers that need a canonical form
            (case-folding, normalization) must apply it before calling.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 chars).
    """
    return hashlib.sha256(value.encode()).hexdigest()
