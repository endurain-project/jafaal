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
  against a separate asymmetric allow-list (blocking RS256→HS256 confusion).
- **Refresh-token rotation with reuse detection.** Every refresh rotates the
  token; presenting an already-rotated token past a short grace window is treated
  as **theft** and invalidates the entire token family. A racing/duplicate
  refresh *within* grace replays the same replacement idempotently.
- **CSRF binding** for web clients, with an OAuth 2.1 bootstrap rule for page
  reloads. Refresh cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in
  deployed environments.

### MFA

- **TOTP** with QR provisioning and **single-use backup codes**.
- **Replay protection**: a matched TOTP timestep is recorded and a second use
  within the validity window is rejected (constant-time comparison throughout).

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

## Deployment hardening

JAFAAL runs out of the box in a single process, but a production deployment
should address two silent-by-default footguns — `create_auth_router()` logs a
startup **warning** for each:

1. **Inject a real rate limiter.** The default is a no-op, so endpoints are not
   rate-limited until you call `jafaal.configure_rate_limiter(...)` (per-account
   progressive lockout still applies). Pass it via
   `create_auth_router(rate_limiter=...)`.
2. **Use a distributed state store for multi-worker deployments.** The in-memory
   `StateStore` is process-local, so multiple workers/replicas would keep lockout
   and TOTP-replay state per worker. Configure a shared backend such as
   [`RedisStateStore`](ports-and-adapters.md#redisstatestore) via
   `jafaal.configure_state_store(...)`.

Also make sure to:

- Provide a high-entropy `secret_key` (≥ 32 bytes) and a valid `fernet_key`.
- Set `trusted_proxies` to your actual proxy addresses when running behind a
  reverse proxy, so client IPs (which key the lockout counters) cannot be
  spoofed.
- Keep `allow_api_key_query_param` disabled unless you specifically need it.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — see
[SECURITY.md](https://codeberg.org/endurain-project/jafaal/src/branch/main/SECURITY.md)
for the disclosure process. Do not open a public issue for a security report.
