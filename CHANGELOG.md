# Changelog

All notable changes to JAFAAL are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

What counts as a breaking change — and what does not — is defined in
[API stability](docs/api-stability.md). In short: the `jafaal` namespace, the
exception `code` slugs, the HTTP surface, the token/cookie wire formats, and the
`jafaal.audit` event slugs are covered by SemVer; anything under `_core` /
`_internal`, log message text, and default security parameters are not.

## [1.0.0]

First release.

### Added

**Authentication**

- Username/password login with Argon2id hashing — the only supported algorithm,
  with transparent rehashing on verify when the cost parameters change.
  Passwords are never truncated.
- Passwords are NFKC-normalized before hashing (NIST SP 800-63B §5.1.1.2), so a
  passphrase enrolled on a composing platform verifies on a decomposing one.
- A `length_only` password policy by default, with a 15-character regular
  minimum (20 for admins). SP 800-63B-4 §3.1.1.2 states verifiers **SHALL NOT**
  impose composition rules; `password_type="strict"` remains available for hosts
  bound by legacy requirements. Every password field shares one transport bound
  (`PASSWORD_FIELD_MAX_LENGTH`), and `PasswordSettings.max_length` is validated
  against it — previously three schemas carried their own literals (128 / none /
  256), so raising the policy past the smallest silently had no effect.
- Progressive lockout on failed logins, keyed per account **and** per source IP,
  so one address cannot cheaply lock out many accounts. The source IP is taken
  from the forwarded chain resolved right-to-left (the first hop not listed in
  `trusted_proxies`), so a client cannot evade the counter — or forge the IP in
  audit records — by prepending its own `X-Forwarded-For` value. The per-IP
  counter is **not** cleared by a successful login: authenticating as an account
  you own says nothing about failures sprayed at other usernames from the same
  address, and clearing it would make "spray, log in, repeat" defeat the tier
  outright. It decays on its own window instead.
- Timing-equalised failure paths, so response time does not reveal whether an
  account exists or is SSO-only. Password length is bounded before any hashing
  work, so an unauthenticated caller cannot force unbounded Argon2 input.
- Breached-password screening (NIST SP 800-63B) via the *Have I Been Pwned*
  range API — free, unauthenticated, and k-anonymous, so only a five-character
  hash prefix ever leaves the process — or an offline host-supplied blocklist. A
  startup warning fires while none is installed: dropping composition rules
  without a blocklist is the wrong half of the guidance.
- Local sign-up with optional email verification and admin approval, and
  enumeration-safe password reset. Sign-up is enumeration-safe too: an already
  registered username or email produces the same status and body as a fresh
  registration, and the password is hashed before the existence check so the
  branch is not visible in response time either. The user row and its credential
  are written in **one transaction**, so a failure between them cannot leave a
  credential-less account squatting the username.
- Reset-request delivery is dispatched to the background rather than awaited
  inline, so a host sink that sends SMTP synchronously cannot make the "account
  exists" branch measurably slower than the other. Probes for unknown addresses
  are audited (`blocked`), so an enumeration sweep leaves a trail instead of
  nothing.
- Login checks `is_verified` as well as `is_active`. The former was never
  consulted; only JAFAAL's own sign-up coupling the two flags hid it, so any
  host repository creating active-but-unverified users — or SSO provisioning,
  which hard-codes `is_active=True` — would have let an unverified address in.
- A password change or reset revokes the account's **API keys** as well as its
  sessions, and marks outstanding reset tokens used. Self-service password
  change now revokes other sessions by default — "change my password" is what a
  user does when they think they are compromised, and leaving the attacker's
  session live is the one outcome that makes it pointless.

**Tokens and sessions**

- JWT access/refresh tokens conforming to RFC 9068 (*JWT Profile for OAuth 2.0
  Access Tokens*), so a resource server can verify them with a stock JWT
  library.
- HS256 by default, or asymmetric signing (RS/PS/ES 256/384/512) with the public
  key published at a JWKS endpoint for stateless verification.
- RFC 8414 authorization-server metadata at
  `/.well-known/oauth-authorization-server`, so a client discovers the issuer,
  JWKS, and endpoint URLs instead of hard-coding them. It carries **no extension
  members** and only IANA-registered values in its `*_auth_methods_supported`
  fields: everything needed to drive JAFAAL is a standard field. `/auth/login`
  is deliberately **not** advertised — it authenticates a first-party user
  directly and is not the (OAuth 2.1-removed) resource-owner password-credentials
  grant. `issuer_derived_metadata_path()` computes the RFC 8414 §3 location for
  a host that wants to publish there as well.
- RFC 6749 §4.1 authorization-code flow with mandatory PKCE (`/auth/authorize` →
  `/auth/token`), driven by registered public clients
  ([`OAuthClient`][jafaal.OAuthClient]). Four bindings must hold for a code to be
  redeemed — PKCE, `client_id`, byte-for-byte `redirect_uri`, and single use —
  and every redemption failure returns the same `invalid_grant` so the endpoint
  is not an oracle. Errors follow §5.2 (`{"error", "error_description"}`) and,
  once the redirect URI validates, §4.1.2.1 (reported *at* that URI).
- **The registered client is the unit of policy.** `token_delivery`
  (`body` per RFC 6749 §5.1, or `cookie` per RFC 9700 §7.2) and an optional scope
  ceiling are properties of the registration, never of the request. On refresh
  the client is read from the token's own `client_id` claim, so a caller cannot
  switch delivery mode or widen scope at rotation time. A plain-`http` redirect
  URI is accepted only for loopback (RFC 8252 §7.3).
- `/auth/token` serves both grants; `/auth/refresh` is an alias for the refresh
  grant that additionally accepts the token from the `HttpOnly` cookie or an
  `Authorization` header.
- Zero-downtime rotation of both the signing key and the at-rest encryption key,
  via verify-/decrypt-only fallbacks. The overlap covers the stored token digests
  too (sessions, API keys, CSRF, password-reset, sign-up, IdP-link, rotated
  refresh tokens), which are MAC'd under HKDF subkeys of `secret_key`: they are
  read under the primary *and* fallback subkeys and re-keyed as they are
  rewritten, so rolling `secret_key` does not log everyone out or invalidate
  every API key.
- Refresh-token rotation with reuse detection: a replay past a short grace window
  invalidates the whole token family, while a racing retry *within* the window
  replays one idempotent result. That replay is single-use — a lost response
  produces exactly one retry, so anything further is reuse of a superseded token
  and invalidates the family too. The claim is an atomic conditional `UPDATE`,
  so concurrent replays cannot both win.
- Rotation itself is a **compare-and-swap** gated on the session still holding
  the digest the caller verified against, so two requests carrying the same
  refresh token cannot both rotate it. The loser gets a defined
  `stale_refresh_token` response instead of colliding on the rotated-token
  unique index and surfacing as a 500.
- **Session lifetime is always bounded.** `absolute_timeout_hours` (30 days by
  default) is enforced regardless of the opt-in idle timeout, and a session's
  `expires_at` is capped at that deadline on every rotation. Previously
  `expires_at` was recomputed as `now + refresh_token_expire_days` each time, so
  a client refreshing once per token lifetime kept one login alive forever — the
  unbounded refresh-token lifetime RFC 9700 §4.14.2 warns against.
- Every response carrying a token — login, `/auth/token`, `/auth/refresh`, and
  the MFA challenge — is sent `Cache-Control: no-store` and `Pragma: no-cache`
  (RFC 6749 §5.1), so no intermediary retains a credential.
- Server-side sessions with an always-enforced absolute lifetime, an optional
  idle timeout, device metadata, and a CSRF token bound to the session. The
  device fingerprint is recorded at login and never rewritten by a refresh:
  rotation carries no new authentication, so letting it relabel the session
  would erase the forensic record and show an attacker's browser as the user's
  own.
- RFC 7662 token introspection and RFC 7009 revocation. `auth:introspect` is
  grantable directly to a service API key (it is outside the catalog tiers, so
  no user holds it — the host allow-list is its gate) and is advertised in
  `scopes_supported`. Revoking an access token while the denylist is off is
  logged and audited rather than silently reported as successful.
- **RFC 6750 challenges carry their error code.** A 401 for a *presented but
  unusable* credential sends `Bearer error="invalid_token", error_description=
  "…"`; a request with no credential at all sends a bare `Bearer`, as §3
  requires. A deactivated or deleted account is a 401 `invalid_token` too — 403
  would tell a bearer its token is otherwise fine, and 404 would make account
  state observable to whoever holds a stale one.
- Refresh-grant failures answer RFC 6749 §5.2 `400 invalid_grant`, matching the
  authorization-code path, instead of leaking "revoked" vs "never valid" through
  a 404.

**Multi-factor**

- TOTP with QR provisioning, single-use backup codes, and single-use enforcement
  of each matched timestep — including the code that completes *enrolment*, so
  no TOTP acceptance point sits outside the replay guard (RFC 6238 §5.2). The
  pending-MFA ticket is bound to the client the password step was started for,
  so a login begun for a narrow, body-delivery client cannot be finished as a
  wide, cookie-delivery one.
- WebAuthn / passkeys: registration, passwordless authentication, and an
  optional second factor after password login. Binding *and* unbinding a passkey
  require step-up verification (NIST SP 800-63B §6.1.2 / §6.1.4): because a
  passkey logs in on its own, a stolen access token must not be able to register
  one — that would be a permanent credential surviving a password change and
  bypassing the account's TOTP factor — nor strip the factors already there.  Passwordless `authenticate/begin` returns a deterministic **decoy**
  `allowCredentials` for an unknown or passkey-less username, so the response
  shape no longer distinguishes accounts or leaks real credential IDs (W3C
  WebAuthn L2 §14.6.3).
- Every factor change — TOTP enable/disable, backup-code regeneration, passkey
  add/delete — emits an `AuthenticatorChanged` notification, so an attacker
  enrolling their own factor cannot do it in silence.- Step-up re-authentication for sensitive operations, including delegation to a
  linked identity provider for SSO-only accounts.

**Identity providers**

- OpenID Connect login and account linking with discovery, PKCE, and full
  ID-token verification (signature against the provider JWKS, plus `iss`,
  `aud`, `exp`, `iat`, `nonce`, `azp`, and `at_hash`). The token's `kid` is
  treated as a hint rather than a requirement — providers that omit it, and
  stale cached key sets, still verify against the published keys — and when the
  provider declares an issuer, a discovery failure is a **failed** login rather
  than an unverified one.
- The discovery document's `issuer` is checked against the configured issuer URL
  (OIDC Discovery 1.0 §4.3, a MUST). Without it the value `iss` is validated
  against is simply whatever the fetched document declared — self-referential,
  so a document served by one provider can claim to be another.
- Only asymmetric JWKS entries are materialised as ID-token verification
  candidates. A symmetric `oct` key can never verify a provider's signature, and
  importing one left a live RS256→HS256 confusion primitive whose harmlessness
  rested entirely on the algorithm allow-list staying correct.
- Adopting an **existing** local account by matching email is opt-in per
  provider (`allow_email_linking`, off by default) and still requires
  `email_verified`. `email_verified` is the provider's *own* assertion, and
  nothing stops a provider asserting it for a domain it has no authority over —
  so in a multi-provider deployment an always-on email fallback would make the
  weakest enabled provider a takeover path for every account. When a link is
  made the account owner is notified out of band via the `IdpAccountLinked`
  event, since it is a new way to sign in that they did not initiate.
- Profile sync carries `email_verified` to the host and **withholds an
  unverified `email` entirely**. Sync runs on every login, so passing one
  through would quietly undo the linking gate — and the local email is where
  password resets are delivered.
- SSRF-guarded outbound calls: scheme allow-list, public-address enforcement on
  every resolved record, and connections pinned to the validated IP so a DNS
  rebind cannot swap in an internal target. Requests that carry credentials —
  the token exchange, userinfo, and RFC 7009 revocation — additionally refuse to
  follow redirects, because a 307/308 preserves the method *and* body and would
  replay the client secret to the redirect target, which the address check does
  not cover.
- Outbound IdP responses (discovery, JWKS, userinfo) are size-capped: a timeout
  bounds how long JAFAAL waits, not how much it accepts, and the JWKS is cached
  — so one hostile response would otherwise be a persistent memory cost.
- ID-token time claims are validated with a configurable clock-skew leeway
  (`id_token_leeway_seconds`, 60s). These clocks belong to someone else, and a
  strict zero rejects a token whose `iat` is a single second ahead.
- An ID token naming a `kid` absent from the cached JWKS triggers one
  cache-bypassing re-fetch (best-effort, falling back to the cached set), so a
  provider rotating its signing keys does not break every login until the
  hour-long TTL lapses.

**Authorization and integration**

- API keys with a host-configured scope allow-list. A key can additionally never
  carry a scope the account minting it does not itself hold, so a credential
  cannot delegate authority its creator lacks.
- Optional `reauthorize_scopes_per_request`: an access token's scopes are
  intersected with the tier its account currently holds, so demoting an
  administrator applies immediately rather than at token expiry. Strictly
  narrowing — a token never gains a scope it was not issued with. API keys are
  narrowed **unconditionally**, since their expiry is optional and they cannot
  rely on lapsing to shed stale authority. Only scopes the catalog governs are
  subject to this, so a service capability such as `auth:introspect` is
  unaffected.
- Scope denials carry an RFC 6750 `WWW-Authenticate: Bearer
  error="insufficient_scope", scope="..."` challenge with a space-delimited
  scope list, so a client can parse what to re-request.
- An extensible scope catalog, surfaced in the Swagger authorize dialog.
- Ports the host implements — `UserRepository`, `SettingsProvider`,
  `AuthEventSink`, `PasswordBreachChecker`, `RateLimiter`, `StateStore` — so the
  library owns no user table and reads no environment variables.
- A batteries-included adapter for every port: `SqlAlchemyUserRepository`,
  `StaticSettingsProvider`, `LoggingAuthEventSink` / `CompositeAuthEventSink`,
  `HibpBreachChecker` / `BlocklistBreachChecker`, `StateStoreRateLimiter`, and
  `RedisStateStore`. The rate limiter uses a **sliding** window (a fixed one
  lets a client spend its whole budget either side of a bucket boundary, at 2x
  the nominal rate) and takes `fail_open=False` for deployments that would
  rather refuse traffic than serve it unthrottled during a store outage.
- Structured security-audit records on a dedicated `jafaal.audit` logger, ready
  for a SIEM without message-string parsing — covering successful state changes
  (MFA enabled/disabled, password change, credential and IdP-link lifecycle,
  session revocation, scope denial) as well as failures.
- Non-blocking `AuthEventSink` delivery: notifications are dispatched off the
  auth path with a per-delivery deadline and a bounded backlog, so a slow SMTP
  server or webhook cannot degrade login. Security-critical notifications
  (account lockout, refresh-token theft) are admitted against a larger reserve,
  so a flood of routine notifications cannot starve out a security signal.
- Framework-agnostic error types mapped to HTTP once at the edge, each carrying
  a stable machine-readable `code`.
- Alembic migrations for JAFAAL's companion tables.

**Packaging**

- Typed (PEP 561), Python 3.12–3.14, tested against SQLite, PostgreSQL and
  MySQL, and against both the in-memory and Redis state stores.
- Optional features behind extras (`mfa`, `sso`, `webauthn`, `redis`,
  `migrations`) that fail fast with an install hint rather than at import time.
- Startup guards that refuse to run a deployed environment without a rate
  limiter, or on the process-local state store. `create_auth_router()` runs the
  full configuration check by default (`verify=False` opts out), so a missing
  host adapter fails at startup with one clear message instead of on the first
  request that needs it.
- `AuthSettings.environment` is validated against a known set rather than being a
  free-form string, so a typo cannot silently disable the deployed-environment
  controls (cookie `Secure`, cookie name prefix, and the two startup guards).
  `staging` joins `production` and `demo` as a deployed environment.

See [Security](https://jafaal.endurain.com/security/) and
[Threat model](https://jafaal.endurain.com/threat-model/) for the security design
and the host's responsibilities.
