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

**Location.** RFC 8414 §3 derives the metadata URL from the issuer identifier by
inserting ``/.well-known/oauth-authorization-server`` between the host and the
issuer's path — so an issuer of ``https://app.example/api/v1`` publishes at
``https://app.example/.well-known/oauth-authorization-server/api/v1``, *not*
under the API mount. :func:`issuer_derived_metadata_path` computes that path.

JAFAAL still serves the document from the aggregate router by default, because
the endpoint URLs *inside* it are built from wherever the host mounted that
router — information only available from the request path of a mounted route.
An absolute app-level route would put the document in the right place with the
wrong endpoints in it, which is worse than the reverse. To publish at the spec
location, mount a second copy on the application::

    app.include_router(
        jafaal.create_metadata_router(path=jafaal.issuer_derived_metadata_path())
    )

That copy resolves its own mount correctly (see :func:`_resolve_api_root`), so
both locations serve an identical document.

**Scope of the document.** JAFAAL is **not a general-purpose OAuth 2.0
authorization server**: there is no consent screen, no client secret, no dynamic
registration, and it issues tokens only for the host's own first-party apps —
never to third-party clients. What it *is* is an RFC 8252 authorization server
for its own public clients, plus a JWT issuer with a JWKS, an introspection
endpoint, and a revocation endpoint. This document advertises exactly that:

* ``authorization_endpoint`` (``/auth/authorize``) starts the authorization-code
  flow for a client registered via :attr:`~jafaal.AuthSettings.oauth_clients`.
  PKCE is mandatory and ``code`` is the only response type — the implicit and
  hybrid flows are omitted because OAuth 2.1 removes them.
* ``token_endpoint`` (``/auth/token``) implements ``authorization_code`` and
  ``refresh_token``. ``/auth/refresh`` remains as an alias serving the refresh
  grant plus JAFAAL's native cookie/header shape.
* ``/auth/login`` is deliberately **not** advertised. It authenticates an end
  user directly with a password and returns JAFAAL's own session tokens (and may
  return a ``202`` MFA challenge instead); it is a first-party login endpoint,
  not an OAuth endpoint. Advertising it would invite a client to attempt the
  resource-owner password-credentials grant, which OAuth 2.1 removes and
  RFC 9700 §2.4 discourages.
* ``token_endpoint_auth_methods_supported`` is ``["none"]``. Stating it matters,
  because RFC 8414 §2 makes ``client_secret_basic`` the default when the field is
  absent, and JAFAAL's clients are public: PKCE, not a client credential, is what
  binds a code to its requester.

The document carries no extension members. Everything a client needs to drive
JAFAAL is here in standard fields; anything that would need a bespoke one is a
sign the endpoint should have been designed differently.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response

import jafaal.scopes as jafaal_scopes
import jafaal.settings as jafaal_settings

__all__ = [
    "METADATA_PATH",
    "create_metadata_router",
    "get_authorization_server_metadata",
    "issuer_derived_metadata_path",
]

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
        "authorization_endpoint": _join_url(auth_root, "/authorize"),
        "token_endpoint": _join_url(auth_root, "/token"),
        "introspection_endpoint": _join_url(auth_root, "/introspect"),
        "revocation_endpoint": _join_url(auth_root, "/revoke"),
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        # The catalog tiers, plus the introspection capability. AUTH_INTROSPECT
        # is deliberately outside the tiers (it is granted to a service API key,
        # never minted into a user's token), but a client reading this document
        # still has to be able to learn the scope it must obtain to call the
        # advertised introspection_endpoint.
        "scopes_supported": sorted(set(jafaal_scopes.get_scope_catalog().admin) | {jafaal_scopes.AUTH_INTROSPECT}),
        # First-party public clients (RFC 8252): the token endpoint
        # authenticates the *user* and binds the code with PKCE, never a client
        # credential.
        "token_endpoint_auth_methods_supported": ["none"],
        # ``introspection_endpoint_auth_methods_supported`` is deliberately
        # absent. RFC 8414 §2 draws its values from the IANA "OAuth Token
        # Endpoint Authentication Methods" registry — all of which describe
        # *client* authentication — and JAFAAL protects introspection with a
        # scoped access token instead (RFC 7662 §2.1's "separate OAuth 2.0
        # access token" model), which has no registered value. Emitting
        # ``"bearer"`` would be an unregistered token that a strict client may
        # reject, and ``"none"`` would claim the endpoint is unprotected. The
        # required scope is discoverable via ``scopes_supported`` instead.
        # RFC 7009: possession of the token is the authorisation to revoke it.
        "revocation_endpoint_auth_methods_supported": ["none"],
        # PKCE is mandatory, and ``plain`` is refused.
        "code_challenge_methods_supported": ["S256"],
    }


def _resolve_api_root(request: Request) -> str:
    """Return the absolute URL of the API root the endpoints hang off.

    The origin is taken from :attr:`~jafaal.AuthSettings.base_url` when it is
    configured, so a forged ``Host`` header cannot make JAFAAL advertise an
    attacker-controlled ``token_endpoint`` to whoever fetches the document. Only
    when no usable ``base_url`` exists does it fall back to the request's own
    origin.

    The mount is recovered from the request path, which takes one of two shapes
    depending on where the document was registered:

    * ``<mount>/.well-known/oauth-authorization-server`` — the aggregate-router
      fallback, where the mount is the prefix; or
    * ``/.well-known/oauth-authorization-server<issuer-path>`` — the RFC 8414 §3
      location, where the mount is the *suffix*.
    """
    settings = jafaal_settings.get_settings()
    configured = settings._base_url_origin
    if configured:
        origin = configured[0]
    else:
        parsed = urlparse(str(request.base_url))
        origin = f"{parsed.scheme}://{parsed.netloc}"

    path = request.url.path
    if path.endswith(METADATA_PATH):
        mount = path[: -len(METADATA_PATH)]
    elif path.startswith(METADATA_PATH):
        mount = path[len(METADATA_PATH) :]
    else:  # pragma: no cover - the route only matches the two shapes above
        mount = ""
    return _join_url(origin, mount)


def issuer_derived_metadata_path() -> str:
    """Return the RFC 8414 §3 metadata path for the configured issuer.

    §3 forms the URL by inserting ``/.well-known/oauth-authorization-server``
    between the issuer's host and its path component — so an issuer of
    ``https://app.example/api/v1`` publishes at
    ``/.well-known/oauth-authorization-server/api/v1``. The naive
    ``<issuer>/.well-known/...`` is *not* the spec location whenever the issuer
    carries a path, which it does for every deployment mounted under an API
    prefix.

    Returns:
        The absolute path to register on the host application.
    """
    issuer_path = urlparse(jafaal_settings.get_settings().resolved_issuer).path.rstrip("/")
    return f"{METADATA_PATH}{issuer_path}"


def create_metadata_router(auth_prefix: str = "/auth", *, path: str = METADATA_PATH) -> APIRouter:
    """Build the router serving the RFC 8414 discovery document.

    The core auth prefix is injected rather than imported because it is a
    deployment choice owned by :class:`jafaal.RouterPrefixes`; the advertised
    endpoint URLs must follow wherever the host actually mounted the router.

    Args:
        auth_prefix: Prefix the core auth router is mounted under.
        path: Route path to expose the document at. Defaults to the aggregate
            root; :func:`jafaal.create_auth_router` passes the issuer-derived
            path when it registers the route on the host application.

    Returns:
        An :class:`~fastapi.APIRouter` exposing ``path``.
    """
    router = APIRouter()

    @router.get(path, tags=["metadata"])
    def authorization_server_metadata(request: Request, response: Response) -> dict[str, Any]:
        """Serve this deployment's OAuth 2.0 authorization-server metadata."""
        response.headers["Cache-Control"] = f"public, max-age={_METADATA_CACHE_MAX_AGE_SECONDS}"
        return get_authorization_server_metadata(
            api_root=_resolve_api_root(request),
            auth_prefix=auth_prefix,
        )

    return router
