# Threat model & security invariants

This page states what JAFAAL defends against, what it delegates to the host, and
the internal invariants the library maintains. Use it to reason about where your
deployment's security boundary sits.

## Trust boundaries

```mermaid
flowchart LR
    client[Browser / mobile app] -->|HTTPS| proxy[Reverse proxy / TLS termination]
    proxy -->|X-Forwarded-For| app[Host FastAPI app + JAFAAL router]
    app --> db[(Database)]
    app --> store[(State store: in-memory / Redis)]
    app -->|OIDC discovery / JWKS / token| idp[External identity provider]
```

- **Host-owned, outside JAFAAL:** TLS termination, the reverse proxy, the rate
  limiter backend, the database and its access control, secret storage/rotation,
  transport headers (HSTS/CSP), and the deployment topology (worker count).
- **JAFAAL-owned:** credential verification, token issuance/validation, session
  and refresh-token lifecycle, MFA, the OIDC client, progressive lockout, and the
  audit stream.

## What JAFAAL defends against

| Threat | Defence |
| --- | --- |
| Password brute-force / credential stuffing | Argon2 hashing, per-account **and** per-source-IP progressive lockout, host rate limiter (required when deployed). |
| Username enumeration | Timing-equalised dummy Argon2 verify on the "user not found" and "SSO-only" branches; generic error messages. |
| JWT forgery / `alg=none` / algorithm confusion | HS256 pinned; the decode allow-list is mandatory and cannot drift from the signing algorithm. |
| OIDC ID-token forgery | Signature verified against the IdP JWKS with an asymmetric-only allow-list (blocks RS256→HS256 confusion); `iss`/`aud`/`exp`/`iat`, `nonce`, `azp`, and (when present) `at_hash` are validated. |
| Refresh-token theft / replay | One-time rotation with reuse detection; a replay past the grace window invalidates the whole token family; in-grace retries replay one idempotent result. |
| Second-factor bypass | The MFA step is addressed by an opaque, single-use `mfa_token` issued only to the caller that passed the password step — never by username — so a valid one-time code alone cannot complete a login somebody else's password opened. |
| CSRF (web) | `HttpOnly` + `SameSite=Strict` refresh cookie (primary); `/refresh` rejects any request a browser marks as off-site via the **unforgeable** `Origin` / `Sec-Fetch-Site` headers (an attacker can omit a custom CSRF header, but cannot strip these); HMAC-bound CSRF token; optional `__Secure-`/`__Host-` cookie-name prefix. |
| TOTP replay | Matched timestep is **atomically claimed** single-use (one backend-level compare-and-set, so concurrent uses of one code cannot both win); a second use within the validity window is rejected. Fails **closed** on a state-store outage by default. |
| OAuth authorization-code replay / mix-up | Single-use, atomically-consumed `state`; `state`→IdP binding; PKCE (S256) on both the mobile client flow and the upstream authorization-code exchange to the IdP. |
| SSRF via OIDC URLs | Scheme allow-list (`https` required for IdP endpoints by default), every resolved address must be public, pinned-IP connection (DNS-rebinding defence), guard re-runs on each redirect hop. |
| Source-IP spoofing | Proxy headers honoured only from configured `trusted_proxies`. |
| Secret disclosure at rest | IdP secrets, MFA secrets, rotated refresh tokens, and upstream PKCE verifiers are Fernet-encrypted; every stored token digest (session refresh token, rotated refresh token, CSRF, API keys, password-reset / sign-up / IdP-link tokens) is a keyed HMAC under a **per-purpose HKDF subkey**, so one job's digest can never be replayed as another's. `AuthSettings` redacts all key material from its `repr`. |

## What JAFAAL does NOT do (host responsibilities)

- **Terminate TLS / set transport security headers.** Serve everything over
  HTTPS and set HSTS and a Content-Security-Policy (see
  [Security → Response headers](security.md#response-headers-for-sso-redirect-pages)).
- **Enforce rate limits.** JAFAAL only *tags* sensitive/write endpoints; you
  inject the limiter. In a deployed environment startup **fails closed** without
  one (`allow_no_rate_limit_when_deployed` opts out).
- **Store secrets.** You supply `secret_key` / `fernet_key`; JAFAAL never reads
  the environment. See [Key rotation](key-rotation.md).
- **Provide a distributed state store** for multi-worker deployments (startup
  fails closed on the in-memory store when deployed).
- **Authorize business actions.** JAFAAL authenticates and enforces scopes; your
  application owns per-resource authorization.
- **Breach-screen passwords.** Deployed `password_type="length_only"` requires a
  checker or explicit risk opt-out. HIBP fails open during outages, so continuous
  NIST blocklist alignment requires a local fail-closed checker.

## Security invariants

These hold by construction and are covered by the test suite and the
`import-linter` contracts:

1. **Algorithm pinning.** JWT signing/verification is pinned to the configured
  allow-listed HS256, RSA, RSA-PSS, or ECDSA algorithm; upstream ID-token
  verification accepts asymmetric algorithms only. Decode allow-lists are
  always passed explicitly.
2. **Signing keys never leave the process.** `secret_key`/`fernet_key` are used
   to sign/verify/encrypt only; fallbacks are verify-/decrypt-only, and both are
   redacted from `AuthSettings.__repr__` so they cannot reach a log line or a
   traceback frame dump. Every keyed digest uses a purpose-specific HKDF subkey
   rather than the raw `secret_key`.
3. **Refresh tokens rotate.** Every successful refresh replaces the token. One
  bounded idempotent retry may receive the same replacement; subsequent reuse
  revokes the family.
4. **Two factors stay two factors.** A pending MFA login is addressed only by
   the opaque ticket handed to the caller that satisfied the password step, and
   that ticket is consumed atomically on success.
5. **Fail closed when deployed.** Missing rate limiter, in-memory state store,
   deployed `length_only` policy without a breach checker, and (by default) a
   TOTP-replay state-store outage all fail closed unless their named risk
   opt-out is set.
5. **No plaintext long-lived secrets at rest.** Passwords are Argon2-hashed;
   opaque tokens are stored as keyed HMAC digests; reversible secrets are
   Fernet-encrypted.
6. **The core never imports an adapter or an optional dependency.** `import
   jafaal` pulls no `redis`/`authlib`/`pyotp`; features fail fast with an install
   hint when used without their extra.
7. **Boundary types stay framework-agnostic.** `JafaalError` subclasses carry
   HTTP hints but import no web framework; one edge handler maps them to HTTP.

## Reporting

Report suspected vulnerabilities privately — see
[SECURITY.md](https://github.com/endurain-project/jafaal/blob/main/SECURITY.md).
Do not open a public issue.
