# Configuration

JAFAAL never reads environment variables or secret files itself. The host
application builds configuration and injects it once at startup. Every setting is
data **you** own.

## `AuthSettings`

Build a frozen, validated [`AuthSettings`][jafaal.AuthSettings] and install it
with [`jafaal.configure`][jafaal.configure]. Misconfiguration fails fast at
construction (e.g. a short signing key or an invalid Fernet key is rejected).

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(
            secret_key="<32+ byte JWT signing secret>",  # HS256 signing key
            fernet_key=Fernet.generate_key().decode(),   # at-rest token encryption
        ),
        base_url="https://app.example.com",
        app_name="Example",           # MFA issuer shown in authenticators
        environment="production",     # drives the cookie Secure flag
    )
)
```

Configuration is **grouped by concern** rather than being one flat list of
options, so you read (and document) only the parts you use. Every group has
working defaults; only `secrets` is required.

| Group | Covers |
|---|---|
| `secrets` | Signing/encryption keys and their rotation fallbacks |
| `tokens` | Algorithm, lifetimes, `iss`/`aud`/`client_id`, skew, revocation toggles |
| `sessions` | Idle/absolute timeout, refresh-cookie name/path/prefix, trusted origins |
| `passwords` | Argon2 cost, maximum accepted length |
| `mfa` | TOTP replay policy |
| `webauthn` | Passkey RP identity and ceremony policy |
| `sso` | Redirects, IdP transport policy, step-up |
| `network` | Trusted proxies, SSRF allow-list, outbound user agent |
| `rate_limits` | Request budgets consumed by your `RateLimiter` |
| `api_keys` | Key prefix, query-string transport toggle |
| `audit` | PII policy for the `jafaal.audit` stream |

```python
jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(secret_key=..., fernet_key=...),
        base_url="https://app.example.com",
        tokens=jafaal.TokenSettings(access_token_expire_minutes=10, leeway_seconds=30),
        sessions=jafaal.SessionSettings(idle_timeout_enabled=True, refresh_cookie_prefix="__Secure-"),
        network=jafaal.NetworkSettings(trusted_proxies=("10.0.0.0/8",)),
    )
)
```

## Registered clients

Every request that issues a token names the client it is for. The registration —
not the request — decides how the tokens are delivered and how wide they may be,
because a value a caller can choose per-request is a value an attacker can
choose.

```python
jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(secret_key=..., fernet_key=...),
        base_url="https://app.example.com",
        oauth_clients=(
            # The first-party web frontend: refresh token as an HttpOnly cookie.
            jafaal.OAuthClient(
                client_id="web",
                token_delivery="cookie",
                name="Example web app",
            ),
            # A native app: the literal RFC 6749 §5.1 response.
            jafaal.OAuthClient(
                client_id="com.example.app",
                redirect_uris=("com.example.app://oauth/callback",),
                name="Example for iOS",
            ),
            # A third-party integration, capped at what it actually needs.
            jafaal.OAuthClient(
                client_id="com.partner.tool",
                redirect_uris=("https://partner.example/callback",),
                scopes=("profile",),
                name="Partner tool",
            ),
        ),
    )
)
```

| Field | Effect |
| --- | --- |
| `client_id` | The identifier the client sends. Any stable opaque string. |
| `redirect_uris` | Where authorization codes may be delivered, matched **byte-for-byte**. Not needed for a client that only uses `/auth/login` and `/auth/refresh`. |
| `token_delivery` | `"body"` (RFC 6749 §5.1, the default) or `"cookie"` (RFC 9700 §7.2 — `HttpOnly` refresh cookie plus a CSRF token). |
| `scopes` | Ceiling on the token's scopes, intersected with what your [`ScopeResolver`][jafaal.ScopeResolver] grants the user. Empty means "whatever the user holds". |

!!! warning "Set a ceiling for anything you do not control"
    JAFAAL has no consent screen, so without `scopes` a registered client
    receives the user's entire account. That is correct for a first-party app
    that *is* the application, and wrong for everything else.

A plain-`http` `redirect_uri` is accepted only for loopback (`127.0.0.1`,
`[::1]`, `localhost`) per RFC 8252 §7.3; anything else must use `https` or a
private-use scheme.

## Native apps: the authorization-code flow

A native app authenticates through the standard RFC 6749 §4.1 authorization-code
flow with PKCE, which every OAuth client library already speaks — AppAuth-iOS,
AppAuth-Android, `openid-client`, MSAL.

Registration is not bureaucracy — it is what makes **exact `redirect_uri`
matching** possible, which RFC 9700 §4.1 requires and which is the control that
stops an authorization code being steered to an attacker's target. Matching is
byte-for-byte: no prefixes, wildcards, or sub-paths. Clients are *public*
(RFC 8252): a native app cannot keep a secret, so PKCE — not client
authentication — binds the code to the requester.

The flow:

```text
GET  /auth/authorize?response_type=code
                    &client_id=com.example.app
                    &redirect_uri=com.example.app://oauth/callback
                    &code_challenge=<S256>&code_challenge_method=S256
                    &state=<opaque>&idp=<provider-slug>
  → 302 to the identity provider
  → (IdP returns to /public/idp/callback/<slug>)
  → 302 to com.example.app://oauth/callback?code=…&state=…

POST /auth/token
     grant_type=authorization_code&code=…&code_verifier=…
     &redirect_uri=com.example.app://oauth/callback&client_id=com.example.app
  → {"access_token": …, "refresh_token": …, "token_type": "Bearer", "expires_in": …, "scope": …}
```

Four bindings must all hold for a code to be redeemed, and each closes a
published attack: PKCE, `client_id`, exact `redirect_uri`, and single use. Only
the digest of a code is stored, so database read access alone does not yield a
redeemable one. Every redemption failure answers the same `invalid_grant`, so the
endpoint cannot be used to probe which codes or clients exist.

Errors follow RFC 6749: §5.2 `{"error", "error_description"}` on `/auth/token`,
and §4.1.2.1 on `/auth/authorize` — an unregistered `client_id` or `redirect_uri`
is *rendered* (there is no verified target to redirect to), and every later
failure is delivered **to** the redirect URI with `error` and `state`, so an app
waiting on its callback listener learns what happened instead of timing out.

`/auth/token` serves both grants — `authorization_code` and `refresh_token` — so
a standard client needs exactly one token URL. `/auth/refresh` remains as an
alias that also accepts the refresh token from the `HttpOnly` cookie or an
`Authorization` header.

!!! note "Scope"
    `/auth/authorize` authenticates through an identity provider (`idp=`).
    Password login has no browser authorization endpoint because JAFAAL ships no
    login UI — a first-party app posts to `/auth/login` with its `client_id`
    directly. That endpoint is not an OAuth grant and is never advertised in
    discovery.

Everything is advertised in the RFC 8414 discovery document at
`/.well-known/oauth-authorization-server`, so a client can be configured from a
single issuer URL.

Every component reads the installed settings through
[`jafaal.get_settings`][jafaal.get_settings]. Re-calling `configure()` replaces
the settings and invalidates settings-derived caches (e.g. the token manager).

### Selected fields

| Field | Default | Purpose |
| --- | --- | --- |
| `secret_key` | — (required) | HMAC key that signs/verifies JWTs (≥ 32 chars). |
| `fernet_key` | — (required) | Fernet key encrypting at-rest tokens (IdP secrets, MFA secret, rotated refresh tokens). |
| `secret_key_fallbacks` | `()` | Extra HMAC keys accepted only when *verifying* JWTs (rotation overlap). |
| `fernet_key_fallbacks` | `()` | Extra Fernet keys accepted only when *decrypting* at-rest tokens (rotation overlap). |
| `access_token_expire_minutes` | `15` | Access-token lifetime. |
| `refresh_token_expire_days` | `7` | Refresh-token lifetime. |
| `leeway_seconds` | `0` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf`; `0` is strict, keep any value small. |
| `algorithm` | `"HS256"` | JWT signing algorithm: `HS256` (symmetric) or an asymmetric RSA/EC algorithm (see [below](#asymmetric-signing-jwks)). |
| `client_id` | `""` | Value of the RFC 9068 `client_id` claim; defaults to the resolved audience. |
| `private_key` | `""` | PEM private key for asymmetric signing (required when `algorithm` is asymmetric). |
| `private_key_fallbacks` | `()` | Verify-only PEM keys kept in the published JWKS during a signing-key rotation. |
| `idle_timeout_hours` | `1` | Idle-session timeout (opt-in via `idle_timeout_enabled`). |
| `absolute_timeout_hours` | `720` | Hard ceiling on session lifetime, measured from creation. **Always enforced**, and `expires_at` is capped at it on every rotation, so refreshing cannot extend a login indefinitely. |
| `base_url` | `""` | Public base URL; default JWT issuer/audience and SSO redirect base. |
| `csrf_trusted_origins` | `()` | Origins allowed to drive the web refresh flow; defaults to the `base_url` origin. **Set this when the frontend is served from a different origin than the API.** |
| `environment` | `"production"` | One of `production`, `demo`, `staging`, `development`, `local`, `test`, `testing`. The first three are treated as **deployed**; anything else is rejected at construction. |
| `refresh_cookie_prefix` | `""` | Optional `__Secure-`/`__Host-` refresh-cookie name prefix, applied only when deployed (`__Host-` requires `refresh_cookie_path="/"`). |
| `allow_query_param` | `False` | Whether API keys may be sent via `?api_key=` (header only by default). |
| `allow_in_memory_state_store_when_deployed` | `False` | Permit the in-memory state store in a deployed environment (single-worker only; otherwise `create_auth_router()` raises at startup). |
| `allow_no_rate_limit_when_deployed` | `False` | Permit a deployed environment with no enforcing rate limiter (otherwise `create_auth_router()`/`verify_configuration()` raise at startup). |
| `denylist_enabled` | `False` | Record & check revoked access-token `jti`s so `/revoke` kills an access token immediately (one state-store lookup per request). |
| `reauthorize_scopes_per_request` | `False` | Intersect an access token's scopes with the tier its account currently holds, so a demotion applies immediately instead of at token expiry. Strictly narrowing; adds no query. |
| `argon2_time_cost` | `3` | Argon2 time cost (iterations) for password hashing. |
| `argon2_memory_cost` | `65536` | Argon2 memory cost, in KiB. |
| `argon2_parallelism` | `4` | Argon2 parallelism (lanes). |
| `max_length` | `128` | Maximum accepted password length (minimum 64), enforced before hashing. Cannot exceed `jafaal.settings.PASSWORD_FIELD_MAX_LENGTH` (1024), the shared bound every password request field carries. |
| `totp_replay_fail_open` | `False` | On a state-store outage, accept a TOTP code without replay protection instead of failing closed (503). |
| `rp_id` | `""` | WebAuthn Relying Party ID (registrable domain, no scheme/port); defaults to the `base_url` host. |
| `rp_name` | `""` | Human-readable RP name shown by the authenticator; defaults to `app_name`. |
| `origins` | `()` | Exact origins (scheme+host+port) a passkey ceremony may complete from; defaults to the `base_url` origin. |
| `user_verification` | `"preferred"` | User-verification requirement (`required`/`preferred`/`discouraged`). |
| `attestation` | `"none"` | Attestation conveyance requested at registration (`none`/`direct`). |
| `second_factor_enabled` | `False` | Require a registered passkey as a second factor after password login. |
| `passkey_login_satisfies_mfa` | `True` | Whether a passwordless passkey login completes on its own for an account that also has TOTP enrolled. The ceremony always forces user verification, so it is possession **and** a PIN/biometric. Set `False` if your policy names TOTP specifically. |
| `challenge_ttl_seconds` | `300` | Lifetime of a WebAuthn challenge held in the state store. |
| `sensitive` | `"10/minute"` | Budget hint for sensitive endpoints. |
| `write` | `"30/minute"` | Budget hint for write endpoints. |
| `trusted_proxies` | `()` | Peers **and forwarding hops** whose `X-Forwarded-For`/`X-Real-IP` are honoured (empty = trust only the direct peer). |
| `ssrf_allowed_hosts` | `()` | Hosts/CIDRs exempted from the SSRF private-address guard. |
| `idp_require_https` | `True` | Require `https` for identity-provider endpoints (authorization, token, userinfo, JWKS, discovery, revocation); set `False` to allow `http://` for local or self-hosted development. |
| `include_pii` | `True` | Include direct identifiers (username/IP/email) in `jafaal.audit` records; set `False` for PII-minimal retention. |

!!! warning "Behind a proxy"
    `trusted_proxies` defaults to `()` — only the direct TCP peer is trusted, so
    `X-Forwarded-For`/`X-Real-IP` from arbitrary clients are ignored (a client
    cannot spoof the IP that keys the progressive-lockout counters). When running
    behind a reverse proxy, set it to your proxy addresses/CIDRs so the real
    client IP is used; `("*",)` trusts every peer (only safe when a trusted proxy
    always overwrites the header).

    **List every hop, not just the direct peer.** The forwarded chain is resolved
    **right to left**, returning the first address that is not listed in
    `trusted_proxies`. That is deliberate: a proxy configured the usual way
    (nginx's `proxy_add_x_forwarded_for`) *appends* the address it observed to
    whatever the client sent, so a request carrying
    `X-Forwarded-For: 1.2.3.4` arrives as `1.2.3.4, <real client>` — the leftmost
    element is entirely attacker-controlled. With a CDN in front of a reverse
    proxy, list both the CDN egress ranges and the proxy, or resolution stops one
    hop short at the CDN edge address.

!!! warning "`environment` is validated"
    `environment` must be one of the values in the table above. It is not a free
    -form label: `is_deployed` gates the refresh cookie's `Secure` flag, the
    `__Secure-`/`__Host-` cookie prefix, and the two fail-closed startup guards,
    so a typo such as `"prod"` would silently switch all four off. An
    unrecognised value raises at `AuthSettings(...)` construction instead. The
    default is the safe one (`"production"`), so forgetting to set it cannot
    weaken a deployment.

!!! warning "Split-origin frontends"
    `/auth/refresh` rejects any request a browser marks as off-site, using the
    unforgeable `Origin` / `Sec-Fetch-Site` headers. If your frontend and API are
    served from different origins (for example `https://app.example.com` calling
    `https://api.example.com`), list the **frontend** origin in
    `csrf_trusted_origins` or every refresh will be rejected with a 403.

## JWT wire format

JAFAAL publishes a [JWKS](#asymmetric-signing-jwks) so third-party resource
servers can verify its access tokens statelessly. The tokens follow RFC 9068,
*JWT Profile for OAuth 2.0 Access Tokens*, so a stock JWT library reads them
without any JAFAAL-specific parsing:

| Claim | Form |
| --- | --- |
| `scope` | `"profile users:read"` — space-delimited string (RFC 6749 §3.3) |
| `sub` | `"42"` — string (RFC 7519 §4.1.2 defines it as StringOrURI) |
| `client_id` | present (RFC 9068 §2.2); see the `client_id` setting |
| `sid` | session identifier (JAFAAL extension) |
| `token_use` | `access` / `refresh` (JAFAAL extension) |

The token's media type lives in the JOSE `typ` **header** — `at+jwt` for access
tokens, `rt+jwt` for refresh tokens — so a resource server can reject a token
minted for another purpose before parsing a single claim.

### Key rotation

Both the JWT signing key and the Fernet encryption key rotate without downtime by
keeping the previous key as a *fallback* for an overlap window. New material is
always produced with the primary key; the fallbacks are verify-/decrypt-only.

```python
jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(
            secret_key=NEW_SIGNING_KEY,                # signs all new JWTs
            secret_key_fallbacks=(OLD_SIGNING_KEY,),   # still verifies tokens signed before rotation
            fernet_key=NEW_FERNET_KEY,                 # encrypts all new at-rest secrets
            fernet_key_fallbacks=(OLD_FERNET_KEY,),    # still decrypts data written with the old key
        ),
        base_url="https://app.example.com",
        app_name="Example",
    )
)
```

Once every token signed with — and every secret encrypted with — the old key has
expired or been re-written, drop the fallback.

## Asymmetric signing & JWKS

By default JAFAAL signs its access/refresh tokens with **HS256** (a shared
secret), so any service that verifies them needs that secret. To let other
services verify tokens **statelessly with a public key** — no secret sprawl —
set an asymmetric `algorithm` and a PEM `private_key`:

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(jafaal.AuthSettings(
    secrets=jafaal.Secrets(
        # STILL required: keys the HMAC hashing of refresh/CSRF tokens.
        secret_key="<32+ byte secret>",
        fernet_key=Fernet.generate_key().decode(),
        private_key=open("jwt-signing-key.pem").read(),
    ),
    base_url="https://app.example.com",
    # or ES256, PS256, RS384/512, ES384/512, PS384/512
    tokens=jafaal.TokenSettings(algorithm="RS256"),
))
```

JAFAAL signs with the private key (tagging each token with the key's RFC 7638
thumbprint as `kid`) and publishes the **public** key(s) as a JSON Web Key Set:

```text
GET  <your-api-root>/.well-known/jwks.json
```

A resource server verifies a JAFAAL access token the same way it would any OIDC
provider's — fetch the JWKS and check the signature and claims (no call back to
JAFAAL):

```python
import jwt                      # PyJWT, in the *resource server*
from jwt import PyJWKClient

jwks = PyJWKClient("https://app.example.com/api/v1/.well-known/jwks.json")
signing_key = jwks.get_signing_key_from_jwt(access_token)
claims = jwt.decode(
    access_token,
    signing_key.key,
    algorithms=["RS256"],
    issuer="https://app.example.com",      # == base_url
    audience="https://app.example.com",    # == base_url
)
assert claims["typ"] == "access"
```

[`get_jwks()`][jafaal.get_jwks] is also exported, so you can serve the set at the
conventional root path `/.well-known/jwks.json` from your own app instead of the
API-root path above.

### Discovery (RFC 8414)

So a resource server does not have to hard-code any of the above, JAFAAL also
publishes an [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) authorization
server metadata document beside the JWKS:

```text
GET  <your-api-root>/.well-known/oauth-authorization-server
```

```json
{
  "issuer": "https://app.example.com",
  "jwks_uri": "https://app.example.com/api/v1/.well-known/jwks.json",
  "authorization_endpoint": "https://app.example.com/api/v1/auth/authorize",
  "token_endpoint": "https://app.example.com/api/v1/auth/token",
  "introspection_endpoint": "https://app.example.com/api/v1/auth/introspect",
  "revocation_endpoint": "https://app.example.com/api/v1/auth/revoke",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": ["none"],
  "scopes_supported": ["identity_providers:read", "profile", "users:read"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true
}
```

The endpoint URLs follow your [`RouterPrefixes`][jafaal.RouterPrefixes] automatically,
and `scopes_supported` reflects the installed scope catalog. The origin is taken
from `base_url` when it is set, so a forged `Host` header cannot make JAFAAL
advertise an attacker-controlled `token_endpoint`.

`authorization_response_iss_parameter_supported` is
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207): every authorization response
carries `iss`, so a client configured against more than one authorization server
can prove which one answered and refuse a code steered in from another (the
mix-up attack). Advertising it is what lets a client *require* the check.

!!! note "`jwks_uri` appears only when you sign asymmetrically"
    Under the default HS256 there is no public key, and the JWKS endpoint
    answers `404`. Advertising a URL whose document is `{"keys": []}` would tell
    a verifier the issuer had rotated every key away — sending it into refresh
    and retry logic — rather than that stateless verification was never on
    offer. Set an asymmetric `algorithm` (with `secrets.private_key`) to publish
    keys.

There are **no extension members**. Everything a client needs to drive JAFAAL is
a standard field; a bespoke one would mean an endpoint a stock OAuth library
cannot call.

!!! warning "What this document does *not* claim"
    JAFAAL is an authorization server for **your own** clients. It has no client
    secrets, no consent screen, and no dynamic registration: clients are
    registered in configuration ([`OAuthClient`][jafaal.OAuthClient]) and are
    public (RFC 8252), with PKCE — not a client credential — binding a code to
    its requester.

    - **`/auth/login` is deliberately not advertised.** It authenticates an end
      user directly and is a first-party API, not an OAuth grant. Advertising it
      would invite a client to attempt the resource-owner password-credentials
      grant, which OAuth 2.1 removes and
      [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) §2.4 discourages.
    - `token_endpoint_auth_methods_supported` is `["none"]` — stating it matters,
      because RFC 8414 otherwise implies `client_secret_basic`.

### Calling the token endpoint

`/auth/token` serves both grants with the standard RFC 6749 request shapes:

=== "Authorization code (RFC 6749 §4.1.3)"

    ```http
    POST /api/v1/auth/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=<code>&code_verifier=<verifier>
    &redirect_uri=<exact registered uri>&client_id=<your client>
    ```

=== "Refresh (RFC 6749 §6)"

    ```http
    POST /api/v1/auth/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token&refresh_token=<token>
    ```

`/auth/refresh` is an alias for the refresh grant that additionally accepts the
token from the `HttpOnly` cookie or an `Authorization` header, for a browser
client that never sees the token.

**Delivery mode is not a request parameter.** Whether the refresh token comes
back in the body (RFC 6749 §5.1) or as an `HttpOnly` cookie (RFC 9700 §7.2) is
fixed by the client's registered `token_delivery`, and on refresh it is read from
the token's own `client_id` claim. A caller cannot switch it, so there is no
header to get wrong and no mismatch to defend against.

Errors follow RFC 6749 §5.2 — `{"error": "invalid_grant", "error_description":
"…"}` with `Cache-Control: no-store` — which is what an OAuth client library
parses.

!!! note "Document location"
    RFC 8414 §3 derives the metadata URL from the issuer identifier. JAFAAL
    cannot know where you mount the aggregate router, so — like the JWKS route —
    it serves the document at the API root.
    [`get_authorization_server_metadata()`][jafaal.get_authorization_server_metadata]
    is exported if you need to serve the identical payload from the strict
    issuer-derived path instead.

!!! note "`secret_key` is always required"
    Even with asymmetric JWTs, `secret_key` still keys the HMAC hashing of
    refresh tokens (reuse detection) and CSRF tokens, so it stays mandatory.

!!! note "EdDSA is not offered yet"
    `EdDSA` is intentionally excluded: the underlying `joserfc` marks the
    `EdDSA` JOSE identifier as deprecated (RFC 9864) and warns on use. Use
    `ES256` (compact) or `RS256` (most widely interoperable) instead.

See [Key rotation](key-rotation.md#rotating-the-asymmetric-signing-key) for
rotating the signing key without downtime.

## Token introspection & revocation

JAFAAL exposes RFC 7662 introspection and RFC 7009 revocation for its own
access/refresh tokens, mounted on the auth router:

- **`POST <api-root>/auth/introspect`** (RFC 7662) returns `{"active": …}` plus
  the token's metadata (`sub`, `scope`, `exp`, `token_use`, `sid`, …). It is
  **protected**: the caller must present a credential (JWT or API key) carrying
  the `auth:introspect` scope. Grant it to a resource-server API key:

    ```python
    import jafaal
    jafaal.configure_api_key_scopes([..., jafaal.AUTH_INTROSPECT])  # "auth:introspect"
    ```

    A token reads as inactive once it expires, its signature/claims don't match,
    its `jti` is revoked, or its session has been ended (logout / `/revoke`).

- **`POST <api-root>/auth/revoke`** (RFC 7009) — present a token **and the
  `client_id` it was issued to**; always returns `200`, even for an unknown
  token.
    - `client_id` is required (RFC 7009 §2.1) and the token must have been
      issued to it (§5). Without that binding, possession of a leaked token is a
      force-logout primitive: anyone who observes a refresh token can end its
      owner's session. A token belonging to a *different* client is treated
      exactly like an unknown one — a silent `200` — so the endpoint does not
      answer "whose token is this?".
    - A **refresh token** deletes its session — always effective. With
      `denylist_enabled=True` the session id is denylisted too, so the access
      tokens minted from the same grant stop working immediately rather than
      lapsing minutes later (§2.1).
    - An **access token** is denylisted by `jti` **only when**
      `denylist_enabled=True`; otherwise the short-lived token
      lapses at expiry. Enable that setting (or `strict_binding`) for
      immediate access-token revocation — each adds one state-store lookup per
      authenticated request.

!!! note "Distributed deployments"
    The access-token denylist lives in the state store, so a multi-worker
    deployment needs a shared backend (e.g.
    [`RedisStateStore`](ports-and-adapters.md#redisstatestore)) for revocation to
    apply across workers — the same requirement as progressive lockout.

## WebAuthn / passkeys

JAFAAL ships passkey (WebAuthn) support as the optional `jafaal[webauthn]` extra
(installs [`py_webauthn`](https://pypi.org/project/webauthn/)). It covers both
**passwordless** login and passkey-as-**second-factor**, including
usernameless/discoverable credentials. Install and configure the Relying Party:

```bash
pip install 'jafaal[webauthn]'
```

```python
import jafaal

jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(secret_key=..., fernet_key=...),
        base_url="https://app.example",           # rp_id/origins default from this
        webauthn=jafaal.WebAuthnSettings(
            # Set explicitly if base_url is not the passkey origin:
            # rp_id="app.example",                # registrable domain, no scheme/port
            # origins=("https://app.example",),
            user_verification="preferred",        # "required" makes UV (PIN/biometric) a true 2nd factor
            attestation="none",                   # "direct" only if you process attestation
            second_factor_enabled=False,          # True → password login also requires a passkey
        ),
    )
)
```

`rp_id` and `origins` default to the host and origin of
`base_url`; the endpoints return **503** if neither an explicit value nor a
usable `base_url` is configured. The companion table `webauthn_credentials` is
created by `jafaal.map_models` + the packaged migrations (revision
`0002_webauthn_credentials`).

### Endpoints

Mounted by `create_auth_router` (paths relative to your API root):

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `POST /auth/webauthn/register/begin` | access token **+ step-up** | Start registration; returns `navigator.credentials.create()` options. |
| `POST /auth/webauthn/register/complete` | access token | Verify the attestation and store the passkey. |
| `GET /auth/webauthn/credentials` | access token | List the user's passkeys. |
| `POST /auth/webauthn/credentials/{id}/delete` | access token **+ step-up** | Delete a passkey. |
| `POST /public/webauthn/authenticate/begin` | anonymous | Start passwordless login; returns `{challenge_id, options}`. |
| `POST /public/webauthn/authenticate/complete` | anonymous | Verify the assertion and issue JAFAAL tokens. |
| `POST /auth/webauthn/mfa/begin` | anonymous | Start the second-factor ceremony for a pending login. |
| `POST /auth/webauthn/mfa/complete` | anonymous | Verify the second-factor assertion and complete login. |

The `/authenticate/*` and `/mfa/*` completion endpoints take a `client_id`
naming a registered [`OAuthClient`][jafaal.OAuthClient] and return the same token
response as `/auth/login`. Challenges are single-use and expire after
`challenge_ttl_seconds`.

### Second factor

With `webauthn_second_factor_enabled=True`, a successful password login for a
user who has registered passkeys returns the standard **MFA-required** response
(`202` for web) instead of tokens. The client then completes the pending login
with a passkey via `/auth/webauthn/mfa/begin` → `/auth/webauthn/mfa/complete`
(or, if the account also has TOTP MFA, `/auth/mfa/verify`). Passwordless login is
always available regardless of this flag.

!!! note "Distributed deployments"
    WebAuthn challenges live in the state store, so a multi-worker deployment
    needs a shared backend (e.g.
    [`RedisStateStore`](ports-and-adapters.md#redisstatestore)) — the same
    requirement as progressive lockout.

## Database: your `Base` and the session factory

You own the declarative registry; JAFAAL maps its companion tables into it with
[`map_models`][jafaal.map_models], so both share one metadata. Build your user
model on your own `DeclarativeBase` — call it whatever fits your domain — hand it
to `map_models`, and register a session factory bound to your engine.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
import jafaal
from jafaal import IntPKUserMixin


class Base(DeclarativeBase):
    ...  # your own base — naming conventions, schema, your other models


class Account(IntPKUserMixin, Base):
    __tablename__ = "users"


jafaal.map_models(Base, user_model=Account)

engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # fine for dev/tests; use jafaal.migrations in production (below)
```

The class name is yours; JAFAAL resolves its `users` relationship through the
class you register, not by looking one up by name. The `users` **table** name is
fixed, because JAFAAL's foreign keys reference it.

`map_models(...)` must run once at startup, **after** you define the model and
**before** `create_auth_router()` or any DB use (importing a JAFAAL model before
it is a configuration error). Omit the base — `jafaal.map_models(user_model=...)`
— to use JAFAAL's own convenience `jafaal.orm.Base` instead of owning one.

The reverse relationships (`users_sessions`, `local_credential`, `auth_mfa`, …)
and the `mfa_enabled` property are supplied by the mixin — you declare none of
them. Choose an integer or UUID primary key with
[`IntPKUserMixin`][jafaal.IntPKUserMixin] or
[`UUIDPKUserMixin`][jafaal.UUIDPKUserMixin].

### Supported databases

JAFAAL is database-agnostic — it owns no engine and uses only portable
SQLAlchemy types. The test suite runs on **SQLite**, **PostgreSQL**, and
**MySQL** in CI on every change, so cross-dialect portability is a guarantee
rather than an accident. Use whichever backend your host app already uses (e.g.
`postgresql+psycopg://…`, `mysql+pymysql://…`, or `sqlite:///…`).

!!! warning "SQLite caveats"
    SQLite is ideal for development, tests, and small single-node deployments,
    but it has **no real write concurrency** (writes serialize on a
    database-level lock). Combined with the default in-memory
    [`StateStore`][jafaal.StateStore], a SQLite deployment is effectively
    **single-process**: run a single worker, or move to PostgreSQL/MySQL **and**
    a distributed `StateStore` (e.g.
    [`RedisStateStore`](ports-and-adapters.md#redisstatestore)) for multi-worker
    setups. Note that `Uuid` primary keys and `DateTime(timezone=True)` columns
    are stored differently across dialects (SQLite keeps UUIDs as 32-char hex and
    can return naive datetimes); JAFAAL normalizes timestamps back to
    timezone-aware UTC on read, so this stays transparent to callers.

### Migrations

JAFAAL ships its schema as **Alembic** migrations (the `jafaal[migrations]`
extra) so its companion tables can evolve across releases. They run on a
dedicated version table (`jafaal_alembic_version`) and touch only JAFAAL's own
tables — your `users` table and your Alembic history are left alone.

```python
from jafaal import migrations

migrations.upgrade(engine)                  # create/upgrade JAFAAL's tables
# migrations.stamp(engine)                  # existing DB whose tables already exist
# migrations.verify_schema_current(engine)  # fail fast at startup if not migrated
```

Your `users` table must exist first (JAFAAL's tables reference `users.id`), so
run your own migrations before JAFAAL's. Prefer a single, unified Alembic
history? Point your `env.py` at `jafaal.orm.Base.metadata` and add the package's
`versions` directory to your `version_locations` instead.

## Scopes

JAFAAL ships only auth/identity scopes. Layer your application scopes on top of
`DEFAULT_SCOPE_CATALOG`:

```python
from jafaal import DEFAULT_SCOPE_CATALOG, configure_scopes, configure_api_key_scopes

configure_scopes(
    DEFAULT_SCOPE_CATALOG.extend(
        regular=("reports:read",),
        admin=("reports:read", "reports:write"),
        descriptions={"reports:read": "Read reports", "reports:write": "Manage reports"},
    )
)

# Opt each scope an API key may carry in explicitly (empty by default):
configure_api_key_scopes(["reports:read"])
```

## Rate limiting and the state store

By default JAFAAL runs in a single process with an in-memory
[`StateStore`][jafaal.StateStore] and **no** rate limiting. Both are host
infrastructure you inject:

```python
# jafaal.configure_rate_limiter(StateStoreRateLimiter())  # batteries-included limiter
# jafaal.configure_state_store(...)   # inject Redis for multi-worker lockout state
```

`create_auth_router()` logs a startup **warning** when the no-op rate limiter is
still active, and **refuses to start** (raises `RuntimeError`) when the in-memory
state store is used in a *deployed* environment — set
`allow_in_memory_state_store_when_deployed=True` to override for a single-worker
deployment (see [Security → Deployment hardening](security.md#deployment-hardening)).
The batteries-included
[`StateStoreRateLimiter`](ports-and-adapters.md#statestoreratelimiter) needs no
extra dependency and satisfies the limiter warning. For multi-worker/replica
deployments, also inject a distributed [`StateStore`][jafaal.StateStore] (e.g.
[`RedisStateStore`](ports-and-adapters.md#redisstatestore)); the limiter then
enforces budgets cluster-wide automatically.

Call `jafaal.verify_configuration()` once at startup (e.g. in a FastAPI lifespan
handler) to fail fast if a required component — the settings object, the session
factory, the user repository, or the settings provider — has not been installed,
instead of hitting a `RuntimeError` on the first request that needs it.
