# Security

JAFAAL is designed to own the security-critical path so that embedding
applications inherit strong defaults. This page summarises the built-in
protections and the deployment steps you are responsible for.

## Built-in protections

### Credentials

- **Argon2id** password hashing (via `pwdlib`), with transparent rehashing on
  verify when the configured cost parameters change. It is the only supported
  algorithm: a second one exists only to read hashes you no longer want, and
  every additional verifier is another way to get a password comparison wrong.
- A **timing-equalising dummy verify** on the "user not found" login branch, so
  response time cannot be used to enumerate valid usernames.
- Password hashes live in JAFAAL's own `users_local_credentials` table, never on
  your user row — so SSO-only accounts simply have no credential.

### Tokens & sessions

- **JWTs default to HS256, with opt-in asymmetric signing.** The decode
  allow-list is mandatory (pinned to the configured algorithm), so `alg=none`
  and algorithm-confusion are rejected. Configure an asymmetric algorithm
  (RS256/ES256/…) with a `private_key` to sign with a private key and let
  resource servers verify statelessly via the published JWKS — no shared secret
  (see [Asymmetric signing & JWKS](configuration.md#asymmetric-signing-jwks)).
  OIDC ID tokens are verified against a separate asymmetric allow-list (blocking
  RS256→HS256 confusion), and their `iss`/`aud`/`exp`/`iat`, `nonce`, `azp`, and
  (when present) `at_hash` claims are checked, and the discovery document's
  `issuer` must equal the configured issuer URL (OIDC Discovery §4.3) so `iss`
  anchors to the provider you configured rather than to the document itself.
  When an identity provider declares
  an issuer, **discovery failing is a failed login, not an unverified one**: the
  callback refuses to fall back to trusting the userinfo response alone, so an
  attacker who can disrupt discovery cannot downgrade the flow past ID-token
  verification.
- **Adopting an existing account over SSO is opt-in.** A provider can only
  claim a pre-existing local account by matching email when that provider has
  `allow_email_linking` set *and* asserts `email_verified` — because
  `email_verified` is the provider's own claim, and an always-on email fallback
  would make the weakest enabled provider a takeover path for every account.
  Profile sync withholds an unverified email for the same reason.
- **Refresh-token rotation with reuse detection.** Every refresh rotates the
  token; presenting an already-rotated token past a short grace window is treated
  as **theft** and invalidates the entire token family. A racing/duplicate
  refresh *within* grace replays the same replacement idempotently, **once** — a
  lost response produces exactly one retry, so a second replay is reuse and
  invalidates the family too. Sessions
  store the refresh token as a keyed HMAC-SHA256 digest — unforgeable without
  `secret_key`, and microseconds to verify, since a refresh token is a
  high-entropy server-minted JWT rather than a user-chosen secret.
- **CSRF binding** for web clients, with a bootstrap rule for page reloads (the
  in-memory CSRF token is lost on reload while the `HttpOnly` cookie persists).
  `/refresh` additionally rejects any request the browser marks as
  off-site: `Origin` and `Sec-Fetch-Site` are *forbidden header names*, so page
  script can neither forge nor strip them — unlike a custom `X-CSRF-Token`
  header, which a cross-site attacker simply omits. Set `csrf_trusted_origins`
  when the frontend is served from a different origin than the API. Refresh
  cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in deployed
  environments, with an optional `__Secure-`/`__Host-` name prefix.
- **Per-purpose key derivation.** `secret_key` is never used directly as a MAC
  key. Each job (session refresh-token digest, rotated-token lookup, CSRF, API
  keys, password-reset / sign-up / IdP-link tokens, the WebAuthn user handle)
  gets its own HKDF-SHA256 subkey with a distinct label, so a digest computed
  for one purpose can never be replayed as another.
- **Zero-downtime key rotation.** Both the JWT signing key and the Fernet at-rest
  key accept previous keys as verify-/decrypt-only *fallbacks*
  (`secret_key_fallbacks` / `fernet_key_fallbacks`), so keys rotate without
  invalidating live tokens or stored secrets.

### MFA

- **TOTP** with QR provisioning and **single-use backup codes**.
- **The second factor stays a second factor.** When a password login needs MFA,
  `/auth/login` returns an opaque, single-use `mfa_token` alongside the
  challenge. That ticket — not the username — addresses the pending login at
  `/auth/mfa/verify` and at the WebAuthn second-factor endpoints, so possession
  of a valid one-time code alone cannot complete a login that somebody else's
  password step opened. Hold it in memory, never persist it; it expires in five
  minutes and is consumed atomically on success.
- **Replay protection**: a matched TOTP timestep is *atomically claimed* and a
  second use within the validity window is rejected (constant-time comparison
  throughout). The claim is a single compare-and-set in the state store, so two
  concurrent verifications of the same code cannot both succeed. On a state-store
  outage this fails **closed** by default (configurable via
  `totp_replay_fail_open`).

### Network & abuse

- **SSRF guard** on outbound OIDC calls: the scheme is allow-listed, every
  resolved A/AAAA address must be public (DNS-rebinding defence), and the guard
  re-runs on every redirect hop.
- **HTTPS for identity-provider endpoints** (default). The OIDC client refuses
  `http://` IdP URLs — the browser-facing authorization endpoint and the
  server-side token, userinfo, JWKS, discovery and revocation URLs — so
  authorization codes, tokens and client credentials are never sent in
  cleartext. Set `idp_require_https=False` to allow `http://` for local or
  self-hosted development.
- **Upstream PKCE (S256)** on the authorization-code flow to the IdP: JAFAAL
  sends a per-login `code_challenge` and replays the `code_verifier` (held
  Fernet-encrypted with the `state`) at the token exchange, so an intercepted
  authorization code cannot be redeemed by an attacker.
- **Progressive per-account lockout** (escalating windows) on failed login, MFA,
  and step-up attempts, keyed on a normalised, hashed identifier.
- **Unspoofable client IP.** The lockout and rate-limit keys, and the source IP
  in audit records, come from the forwarded chain resolved **right to left** —
  the first hop that is not listed in `trusted_proxies`. A client cannot pick its
  own apparent address by prepending an `X-Forwarded-For` value (the leftmost
  element is attacker-controlled, because proxies *append*). List every hop your
  infrastructure adds; see [Configuration](configuration.md).
- **Rate limiting** hooks for sensitive/write endpoints (you inject the limiter).

### Error handling

The core raises framework-agnostic `JafaalError` subclasses (no `fastapi`
import) that a single edge handler maps to HTTP once, at the boundary. Each
error carries a stable machine-readable `code` alongside its HTTP `status_code`.

### Audit logging

Every security-relevant event is emitted as a **structured record** on the
dedicated `jafaal.audit` logger, separate from the human-readable `jafaal.*`
application logs. Wire a SIEM or audit sink by attaching a handler and reading
the fields off each record — no message-string parsing:

```python
import logging

audit = logging.getLogger("jafaal.audit")
audit.addHandler(my_json_handler)   # e.g. python-json-logger
audit.setLevel(logging.INFO)
audit.propagate = False             # keep audit off the app log if you prefer
```

Each record carries `event` (a stable slug such as `login.failure`), `outcome`
(`success` / `failure` / `blocked`), and event-specific fields (`user_id`,
`username`, `ip`, `session_id`, `key_prefix`, `token_family_id`, …). The log
message is the event slug, so even a plain-text handler stays readable.

#### Event catalog

The stream records **successes as well as failures**: a trail of nothing but
rejections can tell you an account was attacked, but not whether the attacker
got in and what they changed once there. The slugs are declared on
`jafaal.audit.Event`:

| Area | Events |
| --- | --- |
| Authentication | `login.success`, `login.failure`, `logout`, `lockout.applied` |
| MFA | `mfa.success`, `mfa.failure`, `mfa.enabled`, `mfa.disabled`, `mfa.backup_codes_generated`, `mfa.replay_check_unavailable` |
| Step-up | `step_up.success`, `step_up.failure` |
| WebAuthn | `webauthn.registered`, `webauthn.credential_deleted`, `webauthn.auth_success`, `webauthn.auth_failure` |
| Credentials | `password.changed`, `password.reset_requested`, `password.reset_completed`, `signup.confirmed` |
| Tokens & sessions | `token.refreshed`, `token.revoked`, `token.reuse_grace`, `token.theft_detected`, `session.revoked` |
| API keys | `api_key.created`, `api_key.revoked`, `api_key.deleted`, `api_key.auth_success`, `api_key.auth_failure` |
| Identity providers | `idp.link_added`, `idp.link_removed`, `idp.email_linked`, `idp.email_link_refused`, `idp.discovery_failed`, `oauth_state.replay_rejected` |
| Authorization | `scope.denied` |

State-changing events an account owner would want to know about
(`mfa.disabled`, `password.changed` by an admin, `api_key.deleted`,
`idp.link_removed`, `scope.denied`) are emitted at `WARNING` so a coarse level
filter still surfaces them.

!!! tip "Actionable security events"
    Beyond the SIEM-facing audit stream, the host
    [`AuthEventSink`][jafaal.AuthEventSink] also receives best-effort
    **security notifications** it can turn into user-facing alerts:
    `on_new_device_login`, `on_account_locked`,
    `on_refresh_token_theft_detected`, and `on_idp_account_linked`. They are
    fire-and-forget and forward-compatible — a sink that does not implement a
    method simply skips it.

    Delivery never runs inline on the auth path: from synchronous code the
    coroutine is handed to a background dispatch loop, so a slow SMTP server or
    webhook cannot pin a request worker. Each delivery is abandoned after
    `jafaal.ports.EVENT_DISPATCH_TIMEOUT_SECONDS` (10s), and events beyond
    `jafaal.ports.MAX_INFLIGHT_EVENTS` (256) concurrent deliveries are **dropped
    and logged** rather than queued without bound. Call
    `jafaal.ports.wait_for_pending_events()` to flush the queue on shutdown.

!!! warning "Audit records are sensitive"
    To be useful for a SIEM, audit records contain identifiers the application
    logs deliberately omit — plaintext usernames from failed logins and client
    IPs. Treat the `jafaal.audit` stream as sensitive and route it accordingly,
    or set `audit_include_pii=False` to drop those identifiers (usernames are
    then emitted only as a one-way hash) for PII-minimal retention.

## Deployment hardening

JAFAAL runs out of the box in a single process, but a *deployed* environment
(`environment="production"` or `"demo"`) **fails closed** at startup —
`create_auth_router()` / `verify_configuration()` raise — on either of these
until you address them (each has an explicit opt-out for the rare case you
accept the risk):

1. **Inject a real rate limiter.** The default is a no-op, so endpoints are not
   rate-limited until you install one (per-account progressive lockout still
   applies). The batteries-included
   [`StateStoreRateLimiter`](ports-and-adapters.md#statestoreratelimiter) needs no
   extra dependency — pass it via `create_auth_router(rate_limiter=...)` or call
   `jafaal.configure_rate_limiter(StateStoreRateLimiter())`. Opt out with
   `allow_no_rate_limit_when_deployed=True`.
2. **Use a distributed state store for multi-worker deployments.** The in-memory
   `StateStore` is process-local, so multiple workers/replicas would keep lockout
   and TOTP-replay state per worker. Configure a shared backend such as
   [`RedisStateStore`](ports-and-adapters.md#redisstatestore) via
   `jafaal.configure_state_store(...)`, or set
   `allow_in_memory_state_store_when_deployed=True` for a single-worker deployment.

Also make sure to:

- Provide a high-entropy `secret_key` (≥ 32 bytes) and a valid `fernet_key`, and
  plan their [rotation](key-rotation.md).
- Set `trusted_proxies` to your actual proxy addresses when running behind a
  reverse proxy, so client IPs (which key the lockout counters) cannot be
  spoofed.
- Keep `allow_query_param` disabled unless you specifically need it.
- Keep the API-key scope allow-list (`configure_api_key_scopes`) as small as the
  integrations genuinely require. A key can additionally never carry a scope the
  account minting it does not itself hold, so allow-listing an admin scope does
  not hand it to regular users — but a tight allow-list is still the first line.

### Optional hardening knobs

- **`refresh_cookie_prefix`** — set to `"__Secure-"` to prove the refresh cookie
  was set over HTTPS (compatible with the default path-scoped cookie), or
  `"__Host-"` for the strongest binding (requires `refresh_cookie_path="/"`, no
  Domain). The prefix is applied only in a deployed environment (browsers reject
  `__Secure-`/`__Host-` cookies sent without `Secure`, which would break local
  http development).
- **`leeway_seconds`** — small clock-skew tolerance (e.g. `30`) applied to
  the `exp`/`nbf` claims of JAFAAL's own JWTs, to avoid spurious 401s across
  slightly-skewed nodes. Defaults to `0` (strict); keep it small.
- **`totp_replay_fail_open`** — leave `False` (default) so TOTP replay
  protection fails closed on a state-store outage; set `True` only if you prefer
  MFA availability over the single-use guarantee during an outage.

### Password policy (NIST SP 800-63B)

The `password_type` on your [`PasswordPolicy`](ports-and-adapters.md) selects the
validation applied at sign-up and password change:

- **`"length_only"`** (the shipped default) — enforces only minimum/maximum
  length. SP 800-63B-4 §3.1.1.2 states verifiers **SHALL NOT** impose composition
  rules, in favour of length plus breached-password screening. Pair it with a
  breach check: install a
  [`PasswordBreachChecker`][jafaal.PasswordBreachChecker] via
  `jafaal.configure_password_breach_checker(...)` (e.g. an HIBP k-anonymity
  lookup or a local blocklist) — it is consulted after the length policy and
  before hashing, and should fail open on an upstream error. JAFAAL logs a
  startup warning while no checker is installed, because dropping composition
  rules without a blocklist is the wrong half of the guidance.
- **`"strict"`** — additionally requires upper/lower/digit/special. Available for
  hosts bound by legacy composition requirements, but it is a deliberate
  deviation from the standard.

`StaticSettingsProvider` defaults to `length_only` with a 15-character regular
minimum (20 for admins) — the length SP 800-63B-4 §3.1.1.1 recommends, not the 8
it merely permits.

Passwords are NFKC-normalized before hashing (§3.1.1.2), so a passphrase enrolled
on one platform verifies on another. Argon2id is the only hashing algorithm and
it never truncates, so `max_length` (default 128, minimum 64) is the sole upper
bound and exists only to cap hashing work on an unauthenticated endpoint.

## Response headers for SSO redirect pages

JAFAAL issues browser redirects for the SSO callback, always to the
`redirect_uri` the initiating client registered and never to a configured
fallback path. The target is matched byte-for-byte against
[`OAuthClient.redirect_uris`][jafaal.OAuthClient] before the flow starts, so
there is no open redirect to defend against — but **setting transport and
content-security headers is the host's responsibility**. On the frontend pages
that receive these redirects, and on your API responses generally, set at least:

```text
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

Guidance specific to the SSO round trip:

- **Scope the CSP `form-action` and `connect-src`** to your own origin and your
  IdP(s) so the authorization request and token exchange cannot be redirected to
  an attacker-controlled endpoint.
- **`frame-ancestors 'none'`** (or a strict allow-list) prevents the login/result
  pages from being framed for clickjacking.
- **`Referrer-Policy: strict-origin-when-cross-origin`** avoids leaking the
  `session_id` / `state` query parameters to third parties via the `Referer`
  header.
- Prefer setting these at the reverse proxy or via a FastAPI middleware so they
  apply uniformly, including to the redirect responses JAFAAL returns.


## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — see
[SECURITY.md](https://codeberg.org/endurain-project/jafaal/src/branch/main/SECURITY.md)
for the disclosure process. Do not open a public issue for a security report.
