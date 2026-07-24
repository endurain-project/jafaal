"""JWKS (JSON Web Key Set) publication for stateless JWT verification.

When JAFAAL signs its access/refresh tokens with an asymmetric algorithm
(RS256/ES256/…), resource servers can verify them **without the signing secret**
by fetching the public keys from a JWKS endpoint. This module exposes both:

* :func:`get_jwks` — the JWK Set as a plain dict, so a host can serve it at the
  conventional root path ``/.well-known/jwks.json`` from its own app; and
* :data:`router` — a ready-made ``GET /.well-known/jwks.json`` route that
  :func:`jafaal.create_auth_router` mounts under the aggregate root.

In symmetric (HS256) mode the set is empty (``{"keys": []}``) — there is no
public key to publish.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response

import jafaal._internal.token_manager as jafaal_token_manager

__all__ = ["get_jwks", "router"]

# Public keys are safe to cache; a short max-age bounds how long a just-rotated
# key takes to propagate to verifiers.
_JWKS_CACHE_MAX_AGE_SECONDS = 300


def get_jwks() -> dict[str, Any]:
    """Return the JWK Set of public keys that verify JAFAAL's JWTs.

    Returns:
        A JWK Set dict (``{"keys": [...]}``). Empty in HS256 (symmetric) mode.

    Raises:
        RuntimeError: If JAFAAL has not been configured yet.
    """
    return jafaal_token_manager.get_token_manager().jwks()


router = APIRouter()


@router.get("/.well-known/jwks.json", tags=["jwks"])
def jwks_endpoint(response: Response) -> dict[str, Any]:
    """Serve the public JWK Set for verifying JAFAAL access/refresh tokens."""
    response.headers["Cache-Control"] = f"public, max-age={_JWKS_CACHE_MAX_AGE_SECONDS}"
    return get_jwks()
