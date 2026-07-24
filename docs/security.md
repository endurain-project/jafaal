# Security

JAFAAL is designed to own the security-critical path so that embedding
applications inherit strong defaults. This page summarises the built-in
protections and the deployment steps you are responsible for.

## Built-in protections

### Credentials

- **Argon2** password hashing (via `pwdlib`) with a bcrypt fallback for legacy
  hashes and transparent rehashing on verify.
- A **timing-equalising dummy verify** on the "user not found" login branch, so
  response time cannot be used to enumerate valid usernames.
- Password hashes live in JAFAAL's own `users_local_credentials` table, never on
  your user row — so SSO-only accounts simply have no credential.

### Tokens & sessions

- **JWTs are pinned to HS256.** The decode allow-list is mandatory, so `alg=none`
  and algorithm-confusion attacks are rejected. OIDC ID tokens are verified
  against a separate asymmetric allow-list (blocking RS256→HS256 confusion), and
  their `iss`/`aud`/`exp`/`iat`, `nonce`, `azp`, and (when present) `at_hash`
  claims are checked.
- **Refresh-token rotation with reuse detection.** Every refresh rotates the
  token; presenting an already-rotated token past a short grace window is treated
  as **theft** and invalidates the entire token family. A racing/duplicate
  refresh *within* grace replays the same replacement idempotently.
- **CSRF binding** for web clients, with an OAuth 2.1 bootstrap rule for page
  reloads. Refresh cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in
  deployed environments, with an optional `__Secure-`/`__Host-` name prefix.
- **Zero-downtime key rotation.** Both the JWT signing key and the Fernet at-rest
  key accept previous keys as verify-/decrypt-only *fallbacks*
  (`secret_key_fallbacks` / `fernet_key_fallbacks`), so keys rotate without
  invalidating live tokens or stored secrets.

### MFA

- **TOTP** with QR provisioning and **single-use backup codes**.
- **Replay protection**: a matched TOTP timestep is recorded and a second use
  within the validity window is rejected (constant-time comparison throughout).
  On a state-store outage this fails **closed** by default (configurable via
  `mfa_totp_replay_fail_open`).

### Network & abuse

- **SSRF guard** on outbound OIDC calls: the scheme is allow-listed, every
  resolved A/AAAA address must be public (DNS-rebinding defence), and the guard
  re-runs on every redirect hop.
- **Progressive per-account lockout** (escalating windows) on failed login, MFA,
  and step-up attempts, keyed on a normalised, hashed identifier.
- **Rate limiting** hooks for sensitive/write endpoints (you inject the limiter).

### Error handling

The core raises framework-agnostic `JafaalError` subclasses (no `fastapi`
import) that a single edge handler maps to HTTP once, at the boundary. Each
error carries a stable machine-readable `code` alongside its HTTP `status_code`.

### Audit logging

Every security-relevant event — login success/failure, progressive lockouts, MFA
failures, refresh-token reuse/theft, API-key authentication, and OAuth state
replay — is emitted as a **structured record** on the dedicated `jafaal.audit`
logger, separate from the human-readable `jafaal.*` application logs. Wire a SIEM
or audit sink by attaching a handler and reading the fields off each record — no
message-string parsing:

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
- Keep `allow_api_key_query_param` disabled unless you specifically need it.

### Optional hardening knobs

- **`refresh_cookie_prefix`** — set to `"__Secure-"` to prove the refresh cookie
  was set over HTTPS (compatible with the default path-scoped cookie), or
  `"__Host-"` for the strongest binding (requires `refresh_cookie_path="/"`, no
  Domain). The prefix is applied only in a deployed environment (browsers reject
  `__Secure-`/`__Host-` cookies sent without `Secure`, which would break local
  http development).
- **`jwt_leeway_seconds`** — small clock-skew tolerance (e.g. `30`) applied to
  the `exp`/`nbf` claims of JAFAAL's own JWTs, to avoid spurious 401s across
  slightly-skewed nodes. Defaults to `0` (strict); keep it small.
- **`mfa_totp_replay_fail_open`** — leave `False` (default) so TOTP replay
  protection fails closed on a state-store outage; set `True` only if you prefer
  MFA availability over the single-use guarantee during an outage.

### Password policy (NIST SP 800-63B)

The `password_type` on your [`PasswordPolicy`](ports-and-adapters.md) selects the
validation applied at sign-up and password change:

- **`"length_only"`** — enforces only minimum/maximum length. This is the choice
  aligned with NIST SP 800-63B, which advises **against** composition rules in
  favour of length plus breached-password screening. Pair it with a longer
  `min_length` and a host-side breach check (e.g. an HIBP k-anonymity lookup).
- **`"strict"`** — additionally requires upper/lower/digit/special. Available for
  hosts bound by legacy composition requirements.

Passwords are never truncated, and `password_max_length` (default 128, minimum
64) bounds input before hashing so long passphrases are supported. Note the
legacy bcrypt verifier silently truncates at 72 bytes; Argon2 (used for all new
hashes) does not.

## Response headers for SSO redirect pages

JAFAAL issues browser redirects for the SSO callback (e.g. to
`sso_login_result_path` / `sso_error_path` with a `session_id` or error query
parameter). JAFAAL validates and constrains these redirect targets (relative
paths or configured custom schemes only — no open redirects), but **setting
transport and content-security headers is the host's responsibility**. On the
frontend pages that receive these redirects, and on your API responses
generally, set at least:

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
