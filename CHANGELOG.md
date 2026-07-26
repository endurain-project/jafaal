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
  so one address cannot cheaply lock out many accounts.
- Timing-equalised failure paths, so response time does not reveal whether an
  account exists or is SSO-only.
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
- Zero-downtime rotation of both the signing key and the at-rest encryption key,
  via verify-/decrypt-only fallbacks.
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
  `aud`, `exp`, `iat`, `nonce`, `azp`, and `at_hash`).
- SSRF-guarded outbound calls: scheme allow-list, public-address enforcement on
  every resolved record, and connections pinned to the validated IP so a DNS
  rebind cannot swap in an internal target.

**Authorization and integration**

- API keys with a host-configured scope allow-list.
- An extensible scope catalog, surfaced in the Swagger authorize dialog.
- Ports the host implements — `UserRepository`, `SettingsProvider`,
  `AuthEventSink`, `PasswordBreachChecker`, `RateLimiter`, `StateStore` — so the
  library owns no user table and reads no environment variables.
- A batteries-included adapter for every port: `SqlAlchemyUserRepository`,
  `StaticSettingsProvider`, `LoggingAuthEventSink` / `CompositeAuthEventSink`,
  `HibpBreachChecker` / `BlocklistBreachChecker`, `StateStoreRateLimiter`, and
  `RedisStateStore`.
- Structured security-audit records on a dedicated `jafaal.audit` logger, ready
  for a SIEM without message-string parsing.
- Framework-agnostic error types mapped to HTTP once at the edge, each carrying
  a stable machine-readable `code`.
- Alembic migrations for JAFAAL's companion tables.

**Packaging**

- Typed (PEP 561), Python 3.12–3.14, tested against SQLite, PostgreSQL and
  MySQL, and against both the in-memory and Redis state stores.
- Optional features behind extras (`mfa`, `sso`, `webauthn`, `redis`,
  `migrations`) that fail fast with an install hint rather than at import time.
- Startup guards that refuse to run a deployed environment without a rate
  limiter, or on the process-local state store.

See [Security](https://jafaal.endurain.com/security/) and
[Threat model](https://jafaal.endurain.com/threat-model/) for the security design
and the host's responsibilities.
