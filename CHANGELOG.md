# Changelog

All notable changes to JAFAAL are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, a minor bump (`0.x`) may contain breaking
changes. Those are listed first in their release, each with the migration step
and a note of any credential the change invalidates. JAFAAL does not carry
compatibility shims for its own earlier formats during the `0.x` series: a
breaking change is a clean break.

## [0.1.0]

First release.

### Added

**Authentication**

- Username/password login with Argon2 hashing (bcrypt verification is retained
  so a host can import existing hashes and have them upgraded transparently on
  first login).
- Progressive lockout on failed logins, keyed per account **and** per source IP,
  so one address cannot cheaply lock out many accounts. The source IP is taken
  from the forwarded chain resolved right-to-left (the first hop not listed in
  `trusted_proxies`), so a client cannot evade the counter — or forge the IP in
  audit records — by prepending its own `X-Forwarded-For` value.
- Timing-equalised failure paths, so response time does not reveal whether an
  account exists or is SSO-only. Password length is bounded before any hashing
  work, so an unauthenticated caller cannot force unbounded Argon2 input.
- Breached-password screening (NIST SP 800-63B) via the *Have I Been Pwned*
  range API — free, unauthenticated, and k-anonymous, so only a five-character
  hash prefix ever leaves the process — or an offline host-supplied blocklist.
- Local sign-up with optional email verification and admin approval, and
  enumeration-safe password reset.

**Tokens and sessions**

- JWT access/refresh tokens conforming to RFC 9068 (*JWT Profile for OAuth 2.0
  Access Tokens*), so a resource server can verify them with a stock JWT
  library.
- HS256 by default, or asymmetric signing (RS/PS/ES 256/384/512) with the public
  key published at a JWKS endpoint for stateless verification.
- RFC 8414 authorization-server metadata at
  `/.well-known/oauth-authorization-server`, so a resource server discovers the
  issuer, JWKS, and endpoint URLs instead of hard-coding them. It advertises only
  what JAFAAL genuinely implements: `refresh_token` is the sole grant and
  `token_endpoint` points at `/auth/refresh`. `/auth/login` is deliberately **not**
  advertised — it authenticates a first-party user directly and is not the
  (OAuth 2.1-removed) resource-owner password-credentials grant.
- `/auth/refresh` accepts the standard RFC 6749 §6 request
  (`grant_type=refresh_token&refresh_token=…`) alongside JAFAAL's cookie/header
  shape, so a stock OAuth client can drive the refresh. `X-Client-Type` is
  optional for that shape (a token in the body implies a non-browser client).
- Zero-downtime rotation of both the signing key and the at-rest encryption key,
  via verify-/decrypt-only fallbacks. The overlap covers the stored token digests
  too (sessions, API keys, CSRF, password-reset, sign-up, IdP-link, rotated
  refresh tokens), which are MAC'd under HKDF subkeys of `secret_key`: they are
  read under the primary *and* fallback subkeys and re-keyed as they are
  rewritten, so rolling `secret_key` does not log everyone out or invalidate
  every API key.
- Refresh-token rotation with reuse detection: a replay past a short grace window
  invalidates the whole token family, while a racing retry *within* the window
  replays one idempotent result.
- Server-side sessions with idle and absolute timeouts, device metadata, and a
  CSRF token bound to the session.
- RFC 7662 token introspection and RFC 7009 revocation.

**Multi-factor**

- TOTP with QR provisioning, single-use backup codes, and single-use enforcement
  of each matched timestep.
- WebAuthn / passkeys: registration, passwordless authentication, and an
  optional second factor after password login.
- Step-up re-authentication for sensitive operations, including delegation to a
  linked identity provider for SSO-only accounts.

**Identity providers**

- OpenID Connect login and account linking with discovery, PKCE, and full
  ID-token verification (signature against the provider JWKS, plus `iss`,
  `aud`, `exp`, `iat`, `nonce`, `azp`, and `at_hash`). The token's `kid` is
  treated as a hint rather than a requirement — providers that omit it, and
  stale cached key sets, still verify against the published keys — and when the
  provider declares an issuer, a discovery failure is a **failed** login rather
  than an unverified one.
- SSRF-guarded outbound calls: scheme allow-list, public-address enforcement on
  every resolved record, and connections pinned to the validated IP so a DNS
  rebind cannot swap in an internal target.

**Authorization and integration**

- API keys with a host-configured scope allow-list. A key can additionally never
  carry a scope the account minting it does not itself hold, so a credential
  cannot delegate authority its creator lacks.
- Optional `reauthorize_scopes_per_request`: an access token's scopes are
  intersected with the tier its account currently holds, so demoting an
  administrator applies immediately rather than at token expiry. Strictly
  narrowing — a token never gains a scope it was not issued with.
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
  `RedisStateStore`.
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
