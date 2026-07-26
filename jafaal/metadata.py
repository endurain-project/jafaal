"""RFC 8414 authorization-server metadata publication.

A resource server (or an SDK) that wants to consume JAFAAL tokens needs three
things: the ``iss`` value to expect, where to fetch the verification keys, and
which endpoints exist. Hard-coding those in every client is exactly the coupling
RFC 8414 exists to remove, so JAFAAL publishes them as a discovery document:

* :func:`get_authorization_server_metadata` — the document as a plain dict, so a
  host can serve it from its own root path (the strict RFC 8414 location); and
* :func:`create_metadata_router` — a ready-made
  ``GET /.well-known/oauth-authorization-server`` route that
  :func:`jafaal.create_auth_router` mounts under the aggregate root, next to the
  JWKS endpoint.

**Location caveat.** RFC 8414 §3 derives the metadata URL from the issuer
identifier. JAFAAL cannot know where the host mounts the aggregate router, so —
like the JWKS route — it serves the document at the API root instead. A
deployment that needs the strict issuer-derived URL should mount the pure
function's output itself; the payload is identical.

**Scope of the document.** JAFAAL is a first-party issuer: it has no client
registry, no authorization endpoint, and no consent screen. The advertised
grants are therefore ``password`` and ``refresh_token`` only, and the token
endpoint performs no client authentication (``token_endpoint_auth_methods_supported``
is ``["none"]``) — stating that explicitly matters, because RFC 8414 §2 makes
``client_secret_basic`` the default when the field is absent.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response

import jafaal.scopes as jafaal_scopes
import jafaal.settings as jafaal_settings

__all__ = ["METADATA_PATH", "create_metadata_router", "get_authorization_server_metadata"]

#: Path the discovery document is served from, relative to the aggregate router.
METADATA_PATH = "/.well-known/oauth-authorization-server"

# The document is public, static per-deployment configuration; a short max-age
# bounds how long a scope-catalog or endpoint change takes to propagate.
_METADATA_CACHE_MAX_AGE_SECONDS = 300


def _join_url(base: str, path: str) -> str:
    """Join a base URL and a path with exactly one separating slash."""
    if not path:
        return base.rstrip("/")
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def get_authorization_server_metadata(*, api_root: str, auth_prefix: str = "/auth") -> dict[str, Any]:
    """Build the RFC 8414 metadata document for this deployment.

    Args:
        api_root: Absolute URL the aggregate auth router is mounted at, e.g.
            ``https://app.example/api/v1``. Endpoint URLs are built from it.
        auth_prefix: Prefix the core auth router is mounted under, i.e.
            :attr:`jafaal.RouterPrefixes.auth`.

    Returns:
        The metadata document, ready to be serialised as JSON.

    Raises:
        RuntimeError: If JAFAAL has not been configured yet.
    """
    settings = jafaal_settings.get_settings()
    auth_root = _join_url(api_root, auth_prefix)
    return {
        "issuer": settings.resolved_issuer,
        "jwks_uri": _join_url(api_root, "/.well-known/jwks.json"),
        "token_endpoint": _join_url(auth_root, "/login"),
        "introspection_endpoint": _join_url(auth_root, "/introspect"),
        "revocation_endpoint": _join_url(auth_root, "/revoke"),
        "grant_types_supported": ["password", "refresh_token"],
        # No authorization endpoint means no response type can be requested.
        # RFC 8414 §2 still requires the member, so it is advertised as empty
        # rather than omitted.
        "response_types_supported": [],
        "scopes_supported": sorted(jafaal_scopes.get_scope_catalog().admin),
        # First-party public clients: the token endpoint authenticates the *user*,
        # never a client credential.
        "token_endpoint_auth_methods_supported": ["none"],
        # RFC 7662 §2.1 permits protecting introspection with a separate access
        # token; JAFAAL requires one carrying the ``auth:introspect`` scope.
        "introspection_endpoint_auth_methods_supported": ["bearer"],
        # RFC 7009: possession of the token is the authorisation to revoke it.
        "revocation_endpoint_auth_methods_supported": ["none"],
        # Mobile clients may bind a login to a PKCE challenge (RFC 7636) and
        # redeem the resulting session for tokens with the verifier.
        "code_challenge_methods_supported": ["S256"],
    }


def _resolve_api_root(request: Request) -> str:
    """Return the absolute URL of the mount point the document is served from.

    The origin is taken from :attr:`~jafaal.AuthSettings.base_url` when it is
    configured, so a forged ``Host`` header cannot make JAFAAL advertise an
    attacker-controlled ``token_endpoint`` to whoever fetches the document. Only
    when no usable ``base_url`` exists does it fall back to the request's own
    origin.
    """
    settings = jafaal_settings.get_settings()
    configured = settings._base_url_origin
    if configured:
        origin = configured[0]
    else:
        parsed = urlparse(str(request.base_url))
        origin = f"{parsed.scheme}://{parsed.netloc}"
    path = request.url.path
    mount = path[: -len(METADATA_PATH)] if path.endswith(METADATA_PATH) else ""
    return _join_url(origin, mount)


def create_metadata_router(auth_prefix: str = "/auth") -> APIRouter:
    """Build the router serving the RFC 8414 discovery document.

    The core auth prefix is injected rather than imported because it is a
    deployment choice owned by :class:`jafaal.RouterPrefixes`; the advertised
    endpoint URLs must follow wherever the host actually mounted the router.

    Args:
        auth_prefix: Prefix the core auth router is mounted under.

    Returns:
        An :class:`~fastapi.APIRouter` exposing :data:`METADATA_PATH`.
    """
    router = APIRouter()

    @router.get(METADATA_PATH, tags=["metadata"])
    def authorization_server_metadata(request: Request, response: Response) -> dict[str, Any]:
        """Serve this deployment's OAuth 2.0 authorization-server metadata."""
        response.headers["Cache-Control"] = f"public, max-age={_METADATA_CACHE_MAX_AGE_SECONDS}"
        return get_authorization_server_metadata(
            api_root=_resolve_api_root(request),
            auth_prefix=auth_prefix,
        )

    return router
