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

- Username/password login with Argon2 hashing (bcrypt verification is retained
  so a host can import existing hashes and have them upgraded transparently on
  first login; bcrypt input is truncated at its 72-byte limit, matching the
  semantics those imported hashes were created with, so a long password can
  never raise where other accounts return a clean 401).
- Passwords are NFKC-normalized before hashing (NIST SP 800-63B §5.1.1.2), so a
  passphrase enrolled on a composing platform verifies on a decomposing one.
- A `length_only` password policy by default, with a 15-character regular
  minimum (20 for admins). SP 800-63B-4 §3.1.1.2 states verifiers **SHALL NOT**
  impose composition rules; `password_type="strict"` remains available for hosts
  bound by legacy requirements.
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
  hash prefix ever leaves the process — or an offline host-supplied blocklist. A
  startup warning fires while none is installed: dropping composition rules
  without a blocklist is the wrong half of the guidance.
- Local sign-up with optional email verification and admin approval, and
  enumeration-safe password reset.

**Tokens and sessions**

- JWT access/refresh tokens conforming to RFC 9068 (*JWT Profile for OAuth 2.0
  Access Tokens*), so a resource server can verify them with a stock JWT
  library.
- HS256 by default, or asymmetric signing (RS/PS/ES 256/384/512) with the public
  key published at a JWKS endpoint for stateless verification.
- RFC 8414 authorization-server metadata at
  `/.well-known/oauth-authorization-server`, so a client discovers the issuer,
  JWKS, and endpoint URLs instead of hard-coding them. It carries **no extension
  members**: everything needed to drive JAFAAL is a standard field. `/auth/login`
  is deliberately **not** advertised — it authenticates a first-party user
  directly and is not the (OAuth 2.1-removed) resource-owner password-credentials
  grant.
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
- Every response carrying a token — login, `/auth/token`, `/auth/refresh`, and
  the MFA challenge — is sent `Cache-Control: no-store` and `Pragma: no-cache`
  (RFC 6749 §5.1), so no intermediary retains a credential.
- Server-side sessions with idle and absolute timeouts, device metadata, and a
  CSRF token bound to the session.
- RFC 7662 token introspection and RFC 7009 revocation.

**Multi-factor**

- TOTP with QR provisioning, single-use backup codes, and single-use enforcement
  of each matched timestep.
- WebAuthn / passkeys: registration, passwordless authentication, and an
  optional second factor after password login. Binding *and* unbinding a passkey
  require step-up verification (NIST SP 800-63B §6.1.2 / §6.1.4): because a
  passkey logs in on its own, a stolen access token must not be able to register
  one — that would be a permanent credential surviving a password change and
  bypassing the account's TOTP factor — nor strip the factors already there.
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
  rebind cannot swap in an internal target. Requests that carry credentials —
  the token exchange, userinfo, and RFC 7009 revocation — additionally refuse to
  follow redirects, because a 307/308 preserves the method *and* body and would
  replay the client secret to the redirect target, which the address check does
  not cover.

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
