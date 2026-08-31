# Changelog

All notable changes to JAFAAL are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

What counts as a breaking change — and what does not — is defined in
[API stability](docs/api-stability.md). During the pre-1.0 series, its public
surface is a compatibility target rather than a frozen guarantee: breaking
changes may ship in a minor release and are documented here. The full
major-version guarantee begins with 1.0.0.

## [0.1.0] - Unreleased

Initial pre-1.0 release. The documented public surface is available for
integration feedback and may still change between v0.x minor releases. The
1.0.0 compatibility guarantees in [API stability](docs/api-stability.md) remain
future-facing until the surface has been validated with production consumers.

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
- `jafaal.set_password()` / `jafaal.clear_password()` write a credential outside
  an HTTP request — the one thing no endpoint can do, since sign-up cannot grant
  `is_superuser`. For seeding the first administrator, a CLI `reset-password`, or
  a migration import; ordinary registration still goes through `/auth/sign-up`.
  Both run the same credential sweep every other password path runs, and it is
  **not optional**, so a reset driven from a script evicts an intruder exactly as
  one driven from the endpoint does. Both perform **no step-up and no
  authorization check** — they cannot, having no request to authenticate — so the
  caller must establish that itself. `human_chosen=False` skips the composition
  policy and breach screening for a secret the host generated, where neither
  applies; it is named for the assertion the caller has to be able to make.
- **`POST /auth/password/user/{user_id}`**, the administrative reset, and
  **`POST /auth/password/renew`**, the owner's way to complete it. The reset
  needs `users:write` *and* step-up from the calling administrator, plus the
  object-level check that stops a scope alone from reaching another account; it
  defaults to requiring the owner to replace the password at first sign-in.
  Renewal is unauthenticated by necessity — the account cannot obtain a token
  until the password is replaced — and is not a step-up bypass: it verifies the
  factors a login would and only proceeds for a credential already flagged,
  answering exactly as bad credentials do otherwise.
- **`POST /auth/password/change`**, the self-service password change. Step-up
  gated (`current_password`, plus `mfa_code` when MFA is enabled), because a
  valid access token alone must not be enough to seize an account. Revokes
  everything the old password could reach while **preserving the caller's own
  session**, so changing a password does not log you out of the device you did
  it from, and reports how many other sessions it ended. It is also the way out
  of a `password_change_required` condition — previously every host had to build
  this endpoint itself.
- **Optional forced password change.** `set_password(..., must_change=True)`
  marks the credential, and login then fails with `password_change_required`
  until a new password is written — so a bootstrap or support-desk password,
  which is known to whoever set it, cannot quietly become a permanent one. Off
  by default. The error is deliberately distinct from a wrong password: reaching
  it already required presenting the correct one, so it leaks nothing, and the
  remedy is to replace the password rather than retry. A transparent Argon2
  rehash on login does **not** clear the flag — only a real password write does.
  The owner completes the required replacement at `/auth/password/renew`;
  `/auth/password/change` serves users who already have an authenticated
  session.

**Tokens and sessions**

- Redirect URI policy now accepts only complete HTTPS URIs, native HTTP
  loopback on `127.0.0.1` or `[::1]`, and reverse-domain private-use schemes.
  HTTPS/private URIs match exactly; only an IP-loopback port may vary between
  registration and authorization. `localhost`, relative/opaque URIs, userinfo,
  fragments, unsafe schemes, and malformed reverse-domain names fail at
  configuration and request time. Private-use registrations must migrate from
  authority syntax such as `com.example.app://callback` to RFC 8252's
  single-slash form, `com.example.app:/callback`.
- Deployed `base_url` and issuer values are now required secure absolute HTTPS
  URLs without userinfo, query, or fragment. Local HTTP development is limited
  to the IP literals `127.0.0.1` and `[::1]`.
- Passing `app=` to `create_auth_router` now mounts RFC 8414 metadata at the
  issuer-derived origin-root path, including pathful issuers, while retaining
  the aggregate compatibility path. Advertised OAuth and JWKS URLs are resolved
  from the actual mounted authorization route under the configured external
  issuer origin, including trusted ASGI `root_path` deployments.
- OAuth authorization, token, introspection, and revocation requests are parsed
  from raw query/form multi-items before schema conversion. Missing, empty,
  malformed, non-text, and repeated parameters now return RFC-shaped
  `invalid_request` responses instead of FastAPI `422` bodies, and duplicate
  `client_id` / `redirect_uri` values are never selected as authorization error
  targets. Errors after one registered client/redirect pair validates return to
  that URI with `iss` and an unambiguous `state`.
- JWT access/refresh tokens conforming to RFC 9068 (*JWT Profile for OAuth 2.0
  Access Tokens*), so a resource server can verify them with a stock JWT
  library.
- The JOSE `typ` header is **verified on decode**, not just written on issue.
  RFC 9068 §4 has the resource server reject a token whose media type is not
  `at+jwt` before it reads a single claim, so a token minted for another purpose
  cannot be replayed as an access token. The comparison ignores case and the
  optional `application/` prefix, per §2.1 and RFC 7519 §5.1, so a token from any
  conforming issuer still verifies. JAFAAL validates the `token_use` payload
  claim as well; the header check is the one the RFC mandates, and it is what
  makes a JAFAAL token verifiable by a third-party resource server that only
  looks at `typ`.
- HS256 by default, or asymmetric signing (RS/PS/ES 256/384/512) with the public
  key published at a JWKS endpoint for stateless verification. Under HS256 there
  is no public key, so the JWKS endpoint answers `404` and `jwks_uri` is omitted
  from the discovery document — serving `{"keys": []}` would tell a verifier the
  issuer had rotated every key away, sending it into refresh and retry logic,
  rather than that stateless verification was never on offer.
- `nbf` is backdated a few seconds from `iat`. A resource server runs on someone
  else's clock and has no access to this deployment's `leeway_seconds`, so
  `nbf == iat` makes a sub-second clock difference reject a token minted moments
  earlier. RFC 7519 §4.1.5 anticipates the allowance; applying it at issuance is
  what makes the token portable without asking every verifier to configure one.
- RFC 8414 authorization-server metadata at the issuer-derived origin-root
  path, so a client discovers the issuer, JWKS, and endpoint URLs instead of
  hard-coding them. It carries **no extension
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
- **The authorization endpoint authenticates locally, not only through an
  identity provider.** Omit `idp` and JAFAAL parks the validated request and
  sends the browser to the host's `login_ui_url` with an `auth_request` handle;
  that page posts the credentials to `/auth/login` with the handle, and JAFAAL
  answers with the redirect carrying the code. MFA and passkey second factors
  work unchanged — the handle rides on the pending-login ticket, so whichever
  factor finishes the login produces the authorization response. Nothing about
  the grant is re-read from the login request: client, redirect URI, PKCE
  challenge and scope all come from the parked request, so a compromised login
  page cannot widen or redirect a grant, and no token passes through the page or
  the address bar. This is what lets a native app use the code flow without ever
  handling the password itself (RFC 8252 §8.1) — previously the flow required a
  configured identity provider, and an app without one had no choice but to
  collect the password.
- RFC 9207 issuer identification: every authorization response — success *and*
  error — carries `iss`, and `authorization_response_iss_parameter_supported` is
  advertised so a client can *require* the check. A client configured against
  more than one authorization server otherwise cannot tell which one answered,
  which is what makes the mix-up attack work; `state` does not close it, because
  the honest server's own `state` is what gets replayed.
- **The client's requested `scope` is a real bound** (RFC 6749 §3.3). It is the
  third narrowing step after the host's `ScopeResolver` and the client's ceiling,
  applied on every issuance path: direct login, the authorization-code exchange
  (persisted on the OAuth state across the browser round trip), and MFA or
  passkey second-factor completion (carried on the pending-login ticket, so
  finishing a login in two steps cannot widen what step one asked for). Rotation
  replays the presented token's own `scope` claim, since §6 forbids a refresh
  from adding a scope the original grant did not carry.
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
- Every response carrying or handling a credential — login, `/auth/token`,
  `/auth/refresh`, the MFA challenge, `/auth/introspect` and `/auth/revoke` — is
  sent `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1;
  RFC 7662 §4), so no intermediary retains one.
- Server-side sessions with an always-enforced absolute lifetime, an optional
  idle timeout, device metadata, and a CSRF token bound to the session. The
  device fingerprint is recorded at login and never rewritten by a refresh:
  rotation carries no new authentication, so letting it relabel the session
  would erase the forensic record and show an attacker's browser as the user's
  own.
- RFC 7662 token introspection and RFC 7009 revocation. `auth:introspect` is
  grantable directly to a service API key (it is outside the catalog tiers, so
  no user holds it — the host allow-list is its gate) and is advertised in
  `scopes_supported`. The introspection response reports the token's use as
  `token_use`, matching the claim it reads: §2.2 already defines `token_type` as
  the RFC 6749 §7.1 type (`Bearer`) and RFC 9068 uses `typ` for the JOSE
  *header*'s media type, and a third spelling of "type" meaning a third thing is
  how a client reads the wrong one.
- **Revocation is bound to the client the token was issued to.** RFC 7009 §2.1
  has a public client identify itself with `client_id` and §5 has the server
  check the token was its own; without both, possession of a leaked token is a
  force-logout primitive — anyone who observes a refresh token can end its
  owner's session. An absent or unregistered `client_id` is `invalid_client`; a
  token belonging to a *different* registered client is treated exactly like an
  unknown one (a silent `200`, per §2.2), so the endpoint does not become an
  oracle for "whose token is this?". Revoking a refresh token additionally
  denylists the session id when `denylist_enabled` is set, so the access tokens
  minted from the same grant stop working immediately (§2.1) instead of lasting
  out their lifetime — deleting the session does not reach them, because
  access-token validation is stateless. Revoking an access token while the
  denylist is off is logged and audited rather than silently reported as
  successful.
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
- Whether a passwordless passkey login completes on its own for an account that
  also has TOTP enrolled is an explicit setting
  (`passkey_login_satisfies_mfa`, default on) rather than an accident of which
  endpoint was called. The passwordless ceremony always forces user
  verification, so a successful assertion is possession *and* a PIN/biometric;
  turn it off for a deployment whose policy names TOTP specifically, and such an
  account is sent to the password + TOTP flow instead.
- Every factor change — TOTP enable/disable, backup-code regeneration, passkey
  add/delete — emits an `AuthenticatorChanged` notification, so an attacker
  enrolling their own factor cannot do it in silence.
- Step-up re-authentication for sensitive operations, including delegation to a
  linked identity provider for SSO-only accounts. `prompt=login` and `max_age`
  are sent so the provider re-prompts, and the callback verifies the resulting
  `auth_time` — a missing or stale one fails closed. Because that verification
  exists on the step-up path and nowhere else, requesting either parameter on
  any *other* flow is **rejected** rather than silently forwarded: an identity
  provider is free to ignore both, so an unverified request is a freshness
  guarantee that does not actually hold.

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
- An RFC 9207 `iss` returned by a provider is verified against that provider's
  configured issuer **before** the code is sent to any token endpoint. The
  callback path, the state's provider binding and the ID token's own `iss` all
  defend against mix-up already, but each of those runs after the code has left;
  this one runs first, which is the point of the parameter. Providers predating
  the extension omit it and are unaffected.
- A provider that refuses the request answers per RFC 6749 §4.1.2.1 — `error`
  and `state`, no `code` — and that response is carried through to the client's
  registered `redirect_uri`, having gone through the same state resolution,
  provider binding and single-use claim as a success. Codes outside the
  RFC 6749 / OIDC Core registries are reported as `access_denied`,
  `error_description` is bounded, and `error_uri` is logged rather than
  forwarded: nothing obliges this server to hand its clients a provider-supplied
  URL that a UI would render as a link.
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
- **One revocation sweep for every credential derived from a password.** Changing
  a password — by the user, by an administrator, or through a reset token —
  revokes the account's sessions, API keys, outstanding reset tokens,
  pending-MFA tickets, step-up grants, and pending passkey-registration
  challenges. The last two matter because neither is obviously a credential: a
  step-up grant is a bearer licence to perform one sensitive operation with no
  factor at all, and `/register/complete` carries no step-up of its own — the
  challenge minted by `/register/begin` *is* the proof that step-up passed, so a
  live one is a licence to bind a passkey. The list lives in one place and is
  tested as a matrix (every credential × every path), because a list restated at
  three call sites is a list that drifts.
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
- A startup warning when tokens are signed with HS256 while registered clients
  exist. The signing secret and the verification key are then the same value, so
  anything able to verify a token can also mint one — a resource server cannot
  verify statelessly without being handed the power to issue. Warned rather than
  refused: a single process that both issues and consumes its own tokens is a
  legitimate deployment, and HS256 is correct there.
- `AuthSettings.environment` is validated against a known set rather than being a
  free-form string, so a typo cannot silently disable the deployed-environment
  controls (cookie `Secure`, cookie name prefix, and the two startup guards).
  `staging` joins `production` and `demo` as a deployed environment.

See [Security](https://jafaal.endurain.com/security/) and
[Threat model](https://jafaal.endurain.com/threat-model/) for the security design
and the host's responsibilities.
