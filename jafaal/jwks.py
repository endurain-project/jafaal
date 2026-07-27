"""JWKS (JSON Web Key Set) publication for stateless JWT verification.

When JAFAAL signs its access/refresh tokens with an asymmetric algorithm
(RS256/ES256/…), resource servers can verify them **without the signing secret**
by fetching the public keys from a JWKS endpoint. This module exposes both:

* :func:`get_jwks` — the JWK Set as a plain dict, so a host can serve it at the
  conventional root path ``/.well-known/jwks.json`` from its own app; and
* :data:`router` — a ready-made ``GET /.well-known/jwks.json`` route that
  :func:`jafaal.create_auth_router` mounts under the aggregate root.

In symmetric (HS256) mode there is no public key to publish. The endpoint then
answers **404** rather than an empty ``{"keys": []}``: an empty key set is a
valid document that says "this issuer has rotated away every key", which sends a
verifier into retry/refresh logic instead of telling it the truth, which is that
stateless verification is not on offer here at all. For the same reason
:func:`~jafaal.metadata.get_authorization_server_metadata` omits ``jwks_uri``
entirely under HS256.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response

import jafaal._internal.token_manager as jafaal_token_manager
import jafaal.exceptions as jafaal_exceptions
import jafaal.settings as jafaal_settings

__all__ = ["get_jwks", "router"]

# Public keys are safe to cache; a short max-age bounds how long a just-rotated
# key takes to propagate to verifiers.
_JWKS_CACHE_MAX_AGE_SECONDS = 300


def get_jwks() -> dict[str, Any]:
    """Return the JWK Set of public keys that verify JAFAAL's JWTs.

    Returns:
        A JWK Set dict (``{"keys": [...]}``). Empty in HS256 (symmetric) mode —
        callers serving this over HTTP should check
        :attr:`~jafaal.settings.TokenSettings.is_asymmetric` first, as the
        packaged route does.

    Raises:
        RuntimeError: If JAFAAL has not been configured yet.
    """
    return jafaal_token_manager.get_token_manager().jwks()


router = APIRouter()


@router.get("/.well-known/jwks.json", tags=["jwks"])
def jwks_endpoint(response: Response) -> dict[str, Any]:
    """Serve the public JWK Set for verifying JAFAAL access/refresh tokens.

    Raises:
        NotFoundError: 404 in symmetric (HS256) mode. There is no public key,
            and answering ``{"keys": []}`` would be a lie a verifier acts on.
    """
    if not jafaal_settings.get_settings().tokens.is_asymmetric:
        raise jafaal_exceptions.NotFoundError(
            "This deployment signs tokens with a symmetric algorithm (HS256), so there is no public key "
            "to publish. Configure an asymmetric algorithm (e.g. tokens.algorithm='ES256' with "
            "secrets.private_key) for resource servers to verify statelessly."
        )
    response.headers["Cache-Control"] = f"public, max-age={_JWKS_CACHE_MAX_AGE_SECONDS}"
    return get_jwks()
