"""OIDC discovery, JWKS retrieval, and ID-token verification.

The half of identity-provider integration that talks to the provider *about the
provider*: fetching its ``.well-known`` document, its key set, and using those to
prove an ID token genuine. It owns the caches and the pooled HTTP client those
operations need.

Separated from :mod:`jafaal.identity_providers.service` because the lifetimes are
different. Discovery data is per-provider and cached for an hour; a login flow is
per-request and touches a database. Keeping them in one class meant every flow
change shared a file with the cryptographic verification path, and the cache
state was reachable from code that had no business with it.

The service holds one of these and delegates; nothing else constructs it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
from joserfc import jwt
from joserfc.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    InvalidPayloadError,
    MissingClaimError,
)

import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.id_token as id_token_verify
import jafaal.settings as jafaal_settings
from jafaal._core import network

if TYPE_CHECKING:
    import jafaal.identity_providers.models as idp_models

logger = logging.getLogger(__name__)


def _idp_require_https() -> bool:
    """Whether identity-provider endpoints must use https (``idp_require_https``)."""
    return jafaal_settings.get_settings().sso.idp_require_https


def _assert_discovered_issuer_matches(idp: idp_models.IdentityProvider, config: dict[str, Any]) -> None:
    """Assert the discovery document's ``issuer`` is the one we asked for.

    OpenID Connect Discovery 1.0 §4.3: *"The ``issuer`` value returned MUST be
    identical to the Issuer URL that was used as the prefix to
    ``/.well-known/openid-configuration``."*

    This is the check that makes ``iss`` mean anything. Without it the value an
    ID token is validated against is simply whatever the fetched document
    declared — self-referential, so a document served from provider A can claim
    to be provider B and every subsequent ``iss`` comparison still passes. In a
    multi-provider deployment that is the difference between "this token came
    from the IdP we configured" and "this token came from *an* IdP".

    Compared with the trailing slash normalised away, since ``https://idp/`` and
    ``https://idp`` are the same issuer and providers are inconsistent about it.

    Args:
        idp: The provider whose document was fetched.
        config: The parsed discovery document.

    Raises:
        IdentityProviderError: If ``issuer`` is missing or does not match.
    """
    declared = config.get("issuer")
    configured = idp.issuer_url or ""
    if not isinstance(declared, str) or declared.rstrip("/") != configured.rstrip("/"):
        logger.error(
            f"OIDC discovery for {idp.name} declared issuer {declared!r}, but it was fetched from {configured!r}"
        )
        jafaal_audit.record(
            jafaal_audit.Event.IDP_DISCOVERY_FAILED,
            outcome=jafaal_audit.Outcome.FAILURE,
            level=logging.ERROR,
            idp=idp.slug,
            reason="issuer_mismatch",
        )
        raise jafaal_exceptions.IdentityProviderError(
            f"Identity provider {idp.name} published a discovery document whose issuer does not match its "
            "configured issuer URL, so its tokens cannot be trusted."
        )


class OidcDiscovery:
    """Cached OIDC discovery, JWKS retrieval, and ID-token verification.

    One instance per :class:`~jafaal.identity_providers.service.IdentityProviderService`.
    Both caches are keyed on admin-controlled values (identity-provider id, JWKS
    URI), so their size is bounded by the number of configured providers rather
    than by request volume.
    """

    def __init__(self) -> None:
        """Build empty caches and defer the HTTP client until first use."""
        self._discovery_cache: dict[int, dict[str, Any]] = {}
        self._cache_expiry: dict[int, datetime] = {}
        self._jwks_cache: dict[str, dict[str, Any]] = {}  # Cache JWKS by issuer URL
        self._cache_ttl = timedelta(hours=1)
        self._http_client: httpx.AsyncClient | None = None
        # Loop the cached client's connection pool is bound to (see
        # _get_http_client): an AsyncClient cannot be shared across loops.
        self._http_client_loop: asyncio.AbstractEventLoop | None = None

    def _prune_expired_caches(self) -> None:
        """
        Evict expired entries from the discovery and JWKS caches.

        Both caches are keyed by admin-controlled values (IdP id /
        JWKS URI), so growth is bounded in practice. Pruning on every
        write keeps memory usage proportional to the number of
        currently-active providers rather than to lifetime churn.
        """
        now = datetime.now(UTC)

        # Discovery cache uses a parallel _cache_expiry map
        expired_idp_ids = [idp_id for idp_id, expires_at in self._cache_expiry.items() if expires_at <= now]
        for idp_id in expired_idp_ids:
            self._discovery_cache.pop(idp_id, None)
            self._cache_expiry.pop(idp_id, None)

        # JWKS cache stores cached_at inline
        expired_jwks_uris = [
            uri
            for uri, entry in self._jwks_cache.items()
            if (entry.get("cached_at") is None) or (now - entry["cached_at"]) >= self._cache_ttl
        ]
        for uri in expired_jwks_uris:
            self._jwks_cache.pop(uri, None)

    async def get_http_client(self) -> httpx.AsyncClient:
        """
        Asynchronously retrieves or creates an instance of httpx.AsyncClient for making HTTP requests.

        If the HTTP client does not already exist, it initializes a new AsyncClient with a timeout of 10 seconds
        and connection limits (maximum 5 keep-alive connections and 10 total connections). Returns the client instance.

        Redirects are followed, but an SSRF request hook re-validates every hop
        (:func:`jafaal._core.network.ssrf_request_hook`) so a 3xx pointing at a
        private/internal address cannot bypass the SSRF guard.

        The client is cached per event loop. ``httpx.AsyncClient`` binds its
        connection pool to the loop that created it, so a cached client reused
        from a *different* loop — a reload-restarted uvicorn worker, a test
        runner that creates a loop per test, a host that runs a second
        ``asyncio.run`` — raises ``Event loop is closed`` or silently leaks the
        old pool. Re-creating on a loop change keeps at most one live client per
        loop and lets the stale one be reclaimed.

        A client that was assigned from outside (no recorded creation loop) is
        returned untouched: its lifecycle belongs to whoever supplied it.

        Returns:
            httpx.AsyncClient: The HTTP client instance for asynchronous requests.
        """
        running_loop = asyncio.get_running_loop()
        if self._http_client is not None and self._http_client_loop in (None, running_loop):
            return self._http_client

        if self._http_client is not None:
            # Bound to a loop we are no longer on: drop the reference rather
            # than awaiting aclose() (which would touch the other loop).
            logger.debug("Rebuilding the IdP HTTP client: the event loop changed")

        self._http_client = httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            # Pin every connection (and each redirect hop) to a validated
            # public IP so the address dialed is the one the SSRF policy
            # checked — closing the DNS-rebinding TOCTOU. The request hook
            # below remains as an early, per-hop URL check (defense in depth).
            transport=network.build_ssrf_guard_transport(
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            ),
            # Re-run the SSRF guard on every request, including each redirect
            # hop, so ``follow_redirects=True`` cannot be abused to reach an
            # internal address via a 3xx from an otherwise-public endpoint.
            event_hooks={"request": [network.ssrf_request_hook]},
            headers={
                "User-Agent": jafaal_settings.get_settings().network.user_agent,
                "Accept": "application/json",
            },
        )
        self._http_client_loop = running_loop
        return self._http_client

    async def aclose(self) -> None:
        """Close the pooled HTTP client and drop the cached discovery/JWKS data.

        Call from the host's ASGI lifespan shutdown (see
        :func:`jafaal.shutdown`). Without it the keep-alive connections to every
        configured identity provider stay open until interpreter exit, which
        shows up as leaked sockets in tests and in reload-driven development.

        Safe to call repeatedly, and safe to call when no client was ever built.
        """
        client = self._http_client
        self._http_client = None
        self._http_client_loop = None
        self._discovery_cache.clear()
        self._cache_expiry.clear()
        self._jwks_cache.clear()
        if client is None or client.is_closed:
            return
        try:
            await client.aclose()
        except Exception as err:  # pragma: no cover - shutdown must never raise
            logger.warning(f"Error closing the IdP HTTP client: {type(err).__name__}", exc_info=err)

    async def fetch_jwks(self, jwks_uri: str) -> dict[str, Any]:
        """
        Fetches the JSON Web Key Set (JWKS) from the identity provider.

        This method retrieves the public keys used to verify JWT signatures from the IdP's
        JWKS endpoint. Results are cached for 1 hour to minimize network requests and
        improve performance.

        The JWKS contains one or more public keys in JWK format. Each key has a 'kid'
        (key ID) that matches the 'kid' in JWT headers, allowing us to find the correct
        key for signature verification.

        Args:
            jwks_uri: The JWKS endpoint URL from OIDC discovery (e.g., https://idp.example.com/jwks)

        Returns:
            A dictionary containing the JWKS response with 'keys' array

        Raises:
            JafaalError: If the JWKS cannot be fetched (network errors, timeouts, invalid JSON)

        Example JWKS response:
        {
            "keys": [
                {
                    "kid": "key-id-1",
                    "kty": "RSA",
                    "use": "sig",
                    "n": "...",  # RSA modulus
                    "e": "..."   # RSA exponent
                }
            ]
        }
        """
        # Check cache first
        now = datetime.now(UTC)
        if jwks_uri in self._jwks_cache:
            cached_data = self._jwks_cache[jwks_uri]
            cached_at = cached_data.get("cached_at")
            if cached_at and (now - cached_at) < self._cache_ttl:
                logger.debug(f"Using cached JWKS for {jwks_uri}")
                return cached_data["jwks"]

        # Fetch JWKS from IdP
        try:
            # SSRF guard: refuse to dial private/internal
            # IPs even though jwks_uri originates from
            # admin configuration. A misconfigured IdP
            # entry pointing at 127.0.0.1 or the cloud
            # metadata service would otherwise let an
            # attacker pivot via signed token replay.
            # Self-hosted IdPs on private networks can
            # be opted in via SSRF_ALLOWED_HOSTS.
            network.reject_private_url(jwks_uri, purpose="oidc_jwks", require_https=_idp_require_https())
            client = await self.get_http_client()
            logger.debug(f"Fetching JWKS from {jwks_uri}")

            response = await client.get(jwks_uri)
            response.raise_for_status()

            jwks = response.json()

            # Validate JWKS structure
            if not isinstance(jwks, dict) or "keys" not in jwks:
                logger.error(f"Invalid JWKS format from {jwks_uri}: missing 'keys' array")
                raise jafaal_exceptions.IdentityProviderError("Identity provider returned invalid JWKS format")

            # Cache the JWKS with timestamp
            self._jwks_cache[jwks_uri] = {"jwks": jwks, "cached_at": now}
            self._prune_expired_caches()

            logger.debug(f"Successfully fetched and cached JWKS from {jwks_uri} ({len(jwks.get('keys', []))} keys)")

            return jwks

        except httpx.TimeoutException as err:
            logger.error(f"Timeout fetching JWKS from {jwks_uri}: {err}", exc_info=err)
            raise jafaal_exceptions.IdentityProviderTimeoutError(
                "Timeout retrieving signing keys from identity provider"
            ) from err
        except httpx.HTTPStatusError as err:
            logger.error(f"HTTP error fetching JWKS from {jwks_uri}: {err.response.status_code}", exc_info=err)
            raise jafaal_exceptions.IdentityProviderError(
                f"Identity provider JWKS endpoint returned error: {err.response.status_code}"
            ) from err
        except json.JSONDecodeError as err:
            logger.error(f"Invalid JSON in JWKS response from {jwks_uri}: {err}", exc_info=err)
            raise jafaal_exceptions.IdentityProviderError("Identity provider returned invalid JWKS JSON") from err
        except jafaal_exceptions.JafaalError:
            # Our own validation errors (e.g. invalid JWKS format, SSRF guard)
            # already carry the right status/type — don't mask them as 500.
            raise
        except Exception as err:
            logger.error(f"Unexpected error fetching JWKS from {jwks_uri}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError("Failed to retrieve signing keys from identity provider") from err

    async def verify_id_token(
        self,
        id_token: str,
        jwks_uri: str,
        expected_issuer: str,
        expected_audience: str,
        expected_nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        """
        Verifies the ID token's signature and claims using JWKS from the identity provider.

        This method performs comprehensive JWT verification following OIDC Core 1.0 spec:
        1. Fetches the JWKS (public keys) from the IdP
        2. Extracts the 'kid' (key ID) from the JWT header
        3. Finds the matching public key in the JWKS
        4. Imports the key based on its type (RSA, EC, or Oct)
        5. Verifies the JWT signature using joserfc
        6. Validates standard claims (iss, aud, exp, iat)
        7. Validates nonce if provided (required for implicit/hybrid flows)
        8. Validates azp (authorized party) and at_hash when applicable

        This replaces the insecure manual JWT decode that was previously used.

        Args:
            id_token: The ID token JWT string from the token response
            jwks_uri: The JWKS endpoint URL to fetch public keys
            expected_issuer: Expected 'iss' claim value (from OIDC discovery)
            expected_audience: Expected 'aud' claim value (client_id)
            expected_nonce: Expected nonce value from session (optional, but recommended)
            access_token: The access token issued alongside the ID token, used to
                verify the ``at_hash`` claim when present (optional).

        Returns:
            Dictionary containing the verified JWT claims (sub, email, name, etc.)

        Raises:
            JafaalError: If verification fails (invalid signature, expired token, claim mismatch)

        Security Notes:
            - BadSignatureError: Token was tampered with or signed by wrong key
            - ExpiredTokenError: Token is past its 'exp' claim
            - InvalidClaimError: iss/aud/nonce doesn't match expected values
            - MissingClaimError: Required claim is missing
            - azp is enforced against client_id for multi-audience tokens
            - at_hash binds the ID token to the issued access token when present
        """
        try:
            # Step 1: Parse JWT header without verification to get 'kid'
            # The ID token has format: header.payload.signature
            parts = id_token.split(".")
            if len(parts) != 3:
                logger.warning(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
                raise jafaal_exceptions.InvalidTokenError("Invalid ID token format")

            # Decode header (first part) to get 'kid' and 'alg'
            header_b64 = parts[0]
            # Add padding if necessary
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header_bytes = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_bytes)

            kid = header.get("kid")
            alg = header.get("alg")

            if not alg:
                logger.warning("ID token header missing 'alg' claim")
                raise jafaal_exceptions.InvalidTokenError("ID token missing algorithm")

            # Reject disallowed algorithms before importing the key.
            # This blocks ``alg=none`` and symmetric ``HS*`` algorithms,
            # which would otherwise enable signature-bypass and RS256→HS256
            # key-confusion attacks against the public JWKS keys.
            if alg not in id_token_verify.ID_TOKEN_ALLOWED_ALGORITHMS:
                logger.warning(f"ID token uses disallowed algorithm: {alg}")
                raise jafaal_exceptions.InvalidTokenError("ID token uses an unsupported signature algorithm")

            logger.debug(f"ID token header: kid={kid}, alg={alg}")

            # Step 2: Fetch JWKS from IdP
            jwks = await self.fetch_jwks(jwks_uri)

            # Step 3/4: Select and import the candidate key(s) from the JWKS.
            #
            # ``kid`` is only a hint: OIDC Core does not require it on the ID
            # token and single-key providers routinely omit it, so demanding one
            # would refuse those IdPs outright. When it is absent (or matches
            # nothing) every usable key in the set is tried instead. That is not
            # a weakening: the signature must still verify against one of the
            # IdP's published keys under the same pinned algorithm allow-list.
            candidate_keys = id_token_verify.select_jwks_keys(jwks, kid)
            if not candidate_keys:
                logger.warning(f"No usable key found in JWKS for kid={kid}")
                raise jafaal_exceptions.InvalidTokenError("ID token signed with unknown key")

            # Step 5: Verify signature and decode claims
            # joserfc will verify the signature using the public key.
            # The ``algorithms`` allow-list is mandatory: it pins the
            # acceptable signature algorithms so a forged ``alg`` header
            # (``none`` or a symmetric ``HS*`` confusion attack) cannot
            # bypass verification, mirroring TokenManager.decode_token.
            decoded = id_token_verify.decode_with_any_key(id_token, candidate_keys)
            claims = decoded.claims

            # Step 5a: Validate claims (iss, aud, exp, iat)
            # This is done separately after decoding in joserfc
            claims_request = jwt.JWTClaimsRegistry(
                iss={"essential": True, "value": expected_issuer},
                aud={"essential": True, "value": expected_audience},
                exp={"essential": True},
                iat={"essential": True},
            )

            # Validate all claims
            claims_request.validate(claims)

            logger.debug(f"Successfully verified ID token signature for sub={claims.get('sub')}")

            # Step 6: Validate nonce if provided
            # The nonce is used to prevent replay attacks in OAuth2/OIDC flows
            if expected_nonce:
                token_nonce = claims.get("nonce")
                if not token_nonce:
                    logger.warning("ID token missing nonce claim but nonce was expected")
                    raise jafaal_exceptions.InvalidTokenError("ID token missing nonce")

                if token_nonce != expected_nonce:
                    logger.warning(f"ID token nonce mismatch: expected {expected_nonce}, got {token_nonce}")
                    raise jafaal_exceptions.InvalidTokenError("ID token nonce mismatch")

            # Step 7: Validate azp (authorized party) — OIDC Core 1.0 §3.1.3.7.
            # If the ID token contains multiple audiences, azp MUST be present;
            # and whenever azp is present it MUST equal the client_id. This stops
            # a token minted for a different client (but listing us in aud) from
            # being accepted here.
            aud_claim = claims.get("aud")
            azp = claims.get("azp")
            if isinstance(aud_claim, list) and len(aud_claim) > 1 and not azp:
                logger.warning("ID token has multiple audiences but no azp claim")
                raise jafaal_exceptions.InvalidTokenError("ID token missing azp for multiple audiences")
            if azp is not None and azp != expected_audience:
                logger.warning(f"ID token azp mismatch: expected {expected_audience}, got {azp}")
                raise jafaal_exceptions.InvalidTokenError("ID token azp mismatch")

            # Step 8: Validate at_hash against the issued access token when both
            # are present — OIDC Core 1.0 §3.1.3.6. Optional for the code flow,
            # but verified opportunistically as defense-in-depth binding the ID
            # token to the access token.
            at_hash_claim = claims.get("at_hash")
            if at_hash_claim and access_token:
                id_token_verify.verify_at_hash(access_token, alg, at_hash_claim)

            # Return verified claims
            return claims

        except BadSignatureError as err:
            logger.warning(f"ID token signature verification failed: {err}", exc_info=err)
            raise jafaal_exceptions.InvalidTokenError("ID token signature is invalid") from err
        except ExpiredTokenError as err:
            logger.warning(f"ID token has expired: {err}", exc_info=err)
            raise jafaal_exceptions.TokenExpiredError("ID token has expired") from err
        except InvalidClaimError as err:
            logger.warning(f"ID token claim validation failed: {err}", exc_info=err)
            raise jafaal_exceptions.InvalidTokenError(f"ID token claim validation failed: {err}") from err
        except MissingClaimError as err:
            logger.warning(f"ID token missing required claim: {err}", exc_info=err)
            raise jafaal_exceptions.InvalidTokenError(f"ID token missing required claim: {err}") from err
        except InvalidPayloadError as err:
            logger.warning(f"ID token payload is invalid: {err}", exc_info=err)
            raise jafaal_exceptions.InvalidTokenError("ID token payload is invalid") from err
        except jafaal_exceptions.JafaalError:
            # Re-raise JafaalErrors from _fetch_jwks or our own validations
            raise
        except Exception as err:
            logger.error(f"Unexpected error verifying ID token: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError("Failed to verify ID token") from err

    async def get_oidc_configuration(self, idp: idp_models.IdentityProvider) -> dict[str, Any] | None:
        """
        Retrieves the OpenID Connect (OIDC) discovery configuration for a given identity provider.
        This method attempts to fetch the OIDC configuration from the provider's well-known discovery endpoint.
        It uses an in-memory cache to avoid redundant network requests and respects a cache TTL (time-to-live).
        If the configuration is cached and not expired, it is returned directly from the cache.
        Otherwise, it fetches the configuration over HTTP, validates its ``issuer``, caches it, and returns the result.
        Args:
            idp (idp_models.IdentityProvider): The identity provider instance containing the issuer URL and unique ID.
        Returns:
            dict[str, Any] | None: The OIDC discovery configuration as a dictionary if successful, or None if fetching fails
            or the issuer URL is not provided.
        Raises:
            IdentityProviderError: If the document's ``issuer`` does not match the
                configured ``issuer_url``. A transport failure returns ``None``;
                this one raises, because it is a misconfiguration or an attack,
                not an outage.
        """
        if not idp.issuer_url:
            return None

        # Check cache
        if idp.id in self._discovery_cache and datetime.now(UTC) < self._cache_expiry.get(
            idp.id, datetime.min.replace(tzinfo=UTC)
        ):
            return self._discovery_cache[idp.id]

        # Construct the discovery URL
        discovery_url = f"{idp.issuer_url.rstrip('/')}/.well-known/openid-configuration"

        try:
            # SSRF guard for the admin-supplied issuer
            # URL: see jwks_uri rationale above.
            network.reject_private_url(discovery_url, purpose="oidc_discovery", require_https=_idp_require_https())
            # Fetch the configuration
            client = await self.get_http_client()
            response = await client.get(discovery_url)

            response.raise_for_status()
            config = response.json()
        except httpx.HTTPStatusError as err:
            logger.warning(
                f"HTTP error fetching OIDC discovery for {idp.name}: {err.response.status_code} - {err.response.text}"
            )
            return None
        except httpx.ConnectError as err:
            logger.error(
                f"Connection error fetching OIDC discovery for {idp.name}. "
                f"URL: {discovery_url}. Error: {err}. "
                f"Check if the service is reachable and not using 'localhost' in Docker."
            )
            return None
        except httpx.RequestError as err:
            logger.warning(f"Request error fetching OIDC discovery for {idp.name}. URL: {discovery_url}. Error: {err}")
            return None
        except jafaal_exceptions.JafaalError as err:
            # SSRF guard or other 4xx from reject_private_url.
            # Log with an actionable hint for the operator
            # so they know about the SSRF_ALLOWED_HOSTS
            # escape hatch for self-hosted IdPs.
            logger.warning(
                f"OIDC discovery for {idp.name} was rejected: "
                f"{err.detail}. URL: {discovery_url}. If this is a "
                f"self-hosted IdP on a private network, add its host "
                f"or CIDR to SSRF_ALLOWED_HOSTS."
            )
            return None
        except Exception as err:
            logger.warning(f"Failed to fetch OIDC discovery for {idp.name}: {err}")
            return None

        # Validated outside the fetch block on purpose: the handlers above turn a
        # transport failure into ``None``, and this must not be swallowed the
        # same way.
        _assert_discovered_issuer_matches(idp, config)

        # Cache the configuration
        self._discovery_cache[idp.id] = config
        self._cache_expiry[idp.id] = datetime.now(UTC) + self._cache_ttl
        self._prune_expired_caches()

        return config

    async def resolve_token_endpoint(self, idp: idp_models.IdentityProvider) -> str:
        """
        Resolve the token endpoint URL for an IdP, using OIDC discovery if needed.

        This helper method centralizes token endpoint resolution logic, trying manual
        configuration first and falling back to OIDC discovery if available.

        Args:
            idp (idp_models.IdentityProvider): The identity provider configuration.

        Returns:
            str: The token endpoint URL.

        Raises:
            JafaalError: If token endpoint cannot be resolved (500 Internal Server Error).

        Note:
            - Manual configuration (idp.token_endpoint) takes precedence
            - Falls back to OIDC discovery (/.well-known/openid-configuration)
            - Discovery failures are logged but don't block if manual endpoint exists
        """
        token_endpoint = idp.token_endpoint

        # Try OIDC discovery if token endpoint not manually configured
        if not token_endpoint and idp.issuer_url:
            try:
                config = await self.get_oidc_configuration(idp)
                if config:
                    token_endpoint = config.get("token_endpoint")
            except Exception as err:
                logger.warning(f"OIDC discovery failed for IdP {idp.name} at {idp.issuer_url}: {err}", exc_info=err)
                # Continue - will raise below if still no endpoint

        if not token_endpoint:
            raise jafaal_exceptions.IdentityProviderError(
                f"Identity provider {idp.name} token endpoint could "
                "not be resolved. Verify the issuer URL is reachable; "
                "if it is on a private network, add its host or CIDR "
                "to SSRF_ALLOWED_HOSTS."
            )

        # SSRF guard: the token endpoint can come from admin config or from
        # the discovery document (whose contents are not otherwise
        # re-validated), so a trusted issuer could still advertise an
        # internal target. Refuse private/internal addresses unless
        # explicitly opted in via SSRF_ALLOWED_HOSTS.
        network.reject_private_url(token_endpoint, purpose="oidc_token", require_https=_idp_require_https())

        return token_endpoint
