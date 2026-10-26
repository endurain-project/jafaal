# Security

JAFAAL owns the security-critical path of its host; `docs/security.md` and `docs/threat-model.md` are authoritative. Update them when a change moves the boundary.

## Secrets and keys
- No hardcoded secrets, signing keys or passwords in code, tests-as-fixtures-for-prod, docs or examples; use generated test values.
- Key material comes from `Secrets`/settings; derive per-purpose keys through `token_hashing` (HKDF `KeyPurpose`) rather than reusing one key.
- Never log or put in an exception message a password, token, key, TOTP code, backup code or authorization code.

## Passwords and credentials
- Argon2id is the only algorithm that hashes; an extra algorithm may verify only, and is removed after migration.
- Keep the timing-equalising dummy verify on the "user not found" branch; do not add an early return that skips it.
- Compare secrets with constant-time comparisons.
- Auth and reset responses never reveal whether an account exists.

## Tokens and sessions
- The JWT decode algorithm allow-list is mandatory and pinned to the configured algorithm; never accept `alg=none` or let a token choose its algorithm.
- Validate `iss`, `aud`, `exp` and the token type on every decode; OIDC ID tokens also `nonce`, `azp` and `at_hash` when present.
- Refresh tokens rotate with reuse detection; a reused token revokes its family. Do not weaken either.
- Sessions keep idle and absolute timeouts and CSRF binding; cookies are `HttpOnly`, `Secure` outside test environments and `SameSite`.
- A new session identifier is issued on login.
- Single-use values (OAuth state, PKCE verifier, authorization code, backup code, reset token, TOTP step) are consumed atomically and are never in a URL.

## Outbound requests and redirects
- Treat discovery, JWKS, userinfo and token-endpoint URLs as untrusted; outbound calls go through `jafaal._core.network` (SSRF guard, scheme/host/port allow-list) with timeouts.
- Redirect URIs are matched exactly against the registered set (`redirect_uris`); no prefix or wildcard matching.
- If discovery fails for a provider with a declared issuer, the login fails; it never falls back to an unverified path.

## Abuse and resource limits
- Rate limit and lock out login, reset, MFA and sign-up flows through the `RateLimiter` port; counters live in the state store so they hold across workers.
- Bound every body, page, result and fan-out; never return an unpaginated list that grows with use.
- Password hashing runs bounded so the endpoint cannot be used for CPU exhaustion.

## Data and injection
- Parameterized queries or ORM expressions only; no string-built SQL.
- JSON, never `pickle`; tokens and keys at rest are hashed or encrypted as the existing stores do.

When you add a mitigation, state what it protects against; when you flag a vulnerability, explain the risk.
