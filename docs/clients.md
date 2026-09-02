# Client integration reference

The HTTP contract a client codes against: endpoints, wire formats, scopes, and
error semantics.

For step-by-step tutorials, see the runnable example and its walkthroughs:
[`examples/`](https://github.com/endurain-project/jafaal/tree/main/examples) —
[web](https://github.com/endurain-project/jafaal/blob/main/examples/web_client.md)
and
[mobile](https://github.com/endurain-project/jafaal/blob/main/examples/mobile_client.md).

Paths below are relative to wherever you mounted the router (the example mounts
it at `/api/v1`), except the RFC 8414 issuer-derived metadata path, which begins
at the public origin root.

This reference is only for trusted, statically configured, first-party public
clients owned by the JAFAAL host. They are registered in
[`AuthSettings.oauth_clients`][jafaal.AuthSettings], use PKCE instead of a client
secret, and do not represent third-party integrations. v0.2 has no consent,
grant, confidential-client, or dynamic-registration surface.

## Registered clients decide the response shape

Every token-issuing request names a `client_id` registered in
[`AuthSettings.oauth_clients`][jafaal.AuthSettings]. **The registration — not the
request — decides delivery mode and the scope ceiling**, so a caller cannot widen
its own grant or switch how the refresh token comes back.

| `token_delivery` | Refresh token arrives as | For |
|---|---|---|
| `"cookie"` | `HttpOnly`, `SameSite=Strict` cookie | Browsers. Page script never touches it (RFC 9700 §7.2) |
| `"body"` | A `refresh_token` field in the JSON | Native apps, which have no cookie jar |

That single setting is the only difference between the web and mobile flows.

## Discovery

| Method | Path | Notes |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server{issuer-path}` | RFC 8414 app-root location. Carries no extension members; omit `{issuer-path}` for a root issuer |
| `GET` | `<api-root>/.well-known/oauth-authorization-server` | Compatibility copy of the same metadata document |
| `GET` | `/.well-known/jwks.json` | RFC 7517. **404 under HS256**, which is correct: there is no public key, and `jwks_uri` is omitted from the metadata rather than serving an empty key set |

Do not hard-code endpoint URLs; read them from the metadata document.

## Authentication

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/auth/login` | form: `username`, `password`, `client_id`, optional `auth_request` | Token bundle, or a `202` MFA challenge |
| `POST` | `/auth/mfa/verify` | JSON: `mfa_token`, `mfa_code`, `client_id` | Token bundle |
| `POST` | `/auth/refresh` | form: `client_id` | Rotated token bundle |
| `POST` | `/auth/password/change` | JSON: `new_password`, `current_password`/`mfa_code` as applicable, optional `revoke_other_sessions` | `{"message", "revoked_sessions"}` |
| `POST` | `/auth/password/renew` | JSON: `username`, `current_password`, `new_password`, `mfa_code` as applicable | `{"message", "revoked_sessions"}` |
| `POST` | `/auth/password/user/{user_id}` | JSON: admin's `current_password`/`mfa_code`, `new_password`, optional `must_change` | `{"message", "revoked_sessions"}` |
| `POST` | `/auth/logout` | form: `client_id` | `{"message": "Logout successful"}` |

`/auth/login` is a **first-party** endpoint, not an OAuth grant. It is
deliberately not the resource-owner password-credentials grant (removed by
OAuth 2.1) and is not advertised in the discovery document.

### Managing MFA

The authenticated self-service endpoints use the `profile` scope:

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/profile/mfa` | none | `{"mfa_enabled": boolean}` |
| `POST` | `/profile/mfa/setup` | none | TOTP secret, QR data URI, and authenticator app name |
| `POST` | `/profile/mfa/enable` | `current_password` when present, plus the new `mfa_code` | Confirmation and one-time backup codes |
| `POST` | `/profile/mfa/disable` | `current_password` when present, plus the current `mfa_code` | Confirmation |
| `POST` | `/profile/mfa/verify` | current `mfa_code` | Confirmation; a backup code is consumed |
| `GET` | `/profile/mfa/backup-codes` | none | Counts only; stored codes are never returned |
| `POST` | `/profile/mfa/backup-codes` | `current_password` when present, plus the current `mfa_code` | Replacement codes, shown once |

Setup does not change the account until `/profile/mfa/enable` confirms a code
from the new secret. Enabling, disabling, and replacing backup codes require
step-up verification; SSO-only accounts may omit `current_password` where the
new or existing MFA factor supplies the required proof.

### Changing a password

`/auth/password/change` requires **step-up**: a valid access token is not enough,
because a password change grants persistent account access. Send
`current_password` when the account has a local password and `mfa_code` when MFA
is enabled. An SSO-only account with no MFA has no factor to verify and is
refused until it re-authenticates with its provider.

On success every credential the old password could still reach is revoked —
other sessions, API keys, outstanding reset tokens, pending MFA tickets, step-up
grants. **The caller's own session is preserved**, so the client keeps its tokens
and the user is not logged out of the device they changed it from. Pass
`revoke_other_sessions: false` for a routine rotation.

This is also how a `password_change_required` condition is cleared.

### Administrative reset

`/auth/password/user/{user_id}` sets another account's password. It needs the
`users:write` scope **and** step-up from the calling administrator, and a
non-superuser can only ever target itself.

By default the owner must replace the new password at first sign-in
(`must_change`), because a password an administrator chose is known to that
administrator — without it, a reset is standing access to the account. The owner
completes the loop at `/auth/password/renew`, which is unauthenticated by
necessity (the account cannot obtain a token until the password is replaced) and
verifies exactly the factors a login would.

> [!IMPORTANT]
> JAFAAL's built-in notion of "may administer" is two tiers: superuser or not.
> If yours is richer — tenancy, support roles, delegated admins — gate this
> endpoint yourself or implement a `ScopeResolver` that reflects your model.
> Shipping it unguarded on a multi-tenant deployment would let any superuser
> reach every tenant.

### Token bundle

Cookie clients:

```json
{
  "session_id": "…",
  "access_token": "eyJ…",
  "csrf_token": "…",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token_expires_in": 604800,
  "scope": "profile users:read identity_providers:read"
}
```

Body clients get `refresh_token` instead of `csrf_token`. `scope` is what the
token **actually carries**, which may be narrower than requested (RFC 6749 §3.3
permits this, and §5.1 requires reporting it) — drive your UI off this field.

### MFA challenge

```json
{
  "mfa_required": true,
  "mfa_token": "…",
  "username": "demo",
  "message": "MFA verification required"
}
```

`mfa_token` is an opaque, single-use, five-minute ticket proving the password
factor was satisfied **by this caller**. Hold it in memory; never persist it.
`username` is echoed for display and is not a credential. `mfa_code` accepts a
TOTP code or a single-use backup code (`XXXX-XXXX`).

## OAuth 2.0

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/authorize` | RFC 6749 §4.1 authorization endpoint |
| `POST` | `/auth/token` | `authorization_code` and `refresh_token` grants |
| `POST` | `/auth/introspect` | RFC 7662; requires an `auth:introspect` token |
| `POST` | `/auth/revoke` | RFC 7009; unknown/mismatched tokens return `200`, unsupported access-token revocation returns `unsupported_token_type` |

`/auth/authorize` query parameters: `response_type=code` (the only supported
value), `client_id`, `redirect_uri`, `code_challenge`,
`code_challenge_method=S256`, and optional `state`, `scope`, `idp`.

Omit `idp` and the browser goes to the host's `login_ui_url` with an
`auth_request` handle, which that page posts back to `/auth/login`. Nothing about
the grant is re-read from the login request — client, redirect URI, PKCE
challenge and scope all come from the parked request — so a compromised login
page cannot widen or redirect a grant.

Four bindings must hold for a code to be redeemed: PKCE, `client_id`,
byte-for-byte `redirect_uri`, and single use. **Every failure returns the same
`invalid_grant`**, so the endpoint is not an oracle. Do not branch on the reason.

Authorization responses — success *and* error — carry `iss` (RFC 9207). Validate
it along with `state`.

## Refresh-token rotation

Every refresh rotates the token.

| Property | Behaviour |
|---|---|
| Rotation | A new refresh token on every refresh; the old one is superseded |
| Grace window | ~60s, so a lost response can be retried idempotently |
| Reuse past grace | Treated as theft — the **entire token family** is invalidated |
| Family scope | Every session descended from that login |

Two client obligations follow: keep exactly **one refresh in flight**, and
persist the rotated token before using it. On refresh failure, do not retry with
the old token — re-authenticate.

## CSRF (cookie clients only)

State-changing requests must carry `X-CSRF-Token`. Two independent layers apply:

1. **Off-site rejection**, always enforced under cookie delivery, using `Origin`
   and `Sec-Fetch-Site`. Both are forbidden header names, so page script cannot
   forge or strip them — unlike a custom header, which a cross-site attacker
   simply omits.
2. **Token binding**, when the client sends one.

`/auth/refresh` accepts a **bootstrap** call with no `X-CSRF-Token`: on page
reload the in-memory tokens are gone while the `HttpOnly` cookie persists. Layer 1
is what makes that safe. If the header *is* sent, it must be valid.

## Scopes

JAFAAL ships only auth/identity scopes; a host extends the catalog with its own
via `DEFAULT_SCOPE_CATALOG.extend(...)`.

| Scope | Tier | Meaning |
|---|---|---|
| `profile` | regular | Privileges over the user's own profile |
| `users:read` | regular | Read privileges over users |
| `identity_providers:read` | regular | Read privileges over identity providers |
| `users:write` | admin | Write privileges over users |
| `sessions:read` / `sessions:write` | admin | View / manage sessions |
| `identity_providers:write` | admin | Configure identity providers |
| `auth:introspect` | — | Call the introspection endpoint |

A credential's authority is bounded three times: the host's `ScopeResolver`, then
the registered client's ceiling, then the client's `scope` request.

## OAuth protocol errors

`/auth/authorize`, `/auth/token`, `/auth/introspect`, and `/auth/revoke`
parse protocol parameters before FastAPI request-model validation. A missing,
empty, non-text, malformed, or repeated parameter receives HTTP `400`
`invalid_request`; an OAuth endpoint never emits FastAPI's `422` detail array.
Repeated extension parameters are rejected too, rather than silently choosing
one value.

Token, introspection, and revocation request errors use the OAuth JSON shape, so
a standard client library parses them unmodified:

```json
{ "error": "invalid_grant", "error_description": "…" }
```

Every such error response carries `Cache-Control: no-store` and `Pragma:
no-cache`. An invalid token submitted to introspection is not a request error;
RFC 7662 returns `{"active": false}`. Revoking an unrecognised token remains a
successful no-op under RFC 7009.

The authorization endpoint has two reporting channels:

- If `client_id` or `redirect_uri` is missing, repeated, unknown, or not a
  registered pair, JAFAAL renders the OAuth JSON error locally and sends no
  `Location` header. It never redirects to an unvalidated or ambiguous target.
- After one client and redirect URI validate, later errors return by `302` to
  that URI with `error`, `error_description`, and `iss`. JAFAAL echoes `state`
  only when the request supplied it exactly once; a repeated state is ambiguous
  and is not selected.

| Status | OAuth error | Meaning |
|---|---|---|
| `400` | `invalid_request` | Missing, empty, malformed, or repeated protocol parameter |
| `400` | `invalid_grant` | Invalid, expired, revoked, mismatched, or already-used authorization code or refresh token |
| `400` | `unsupported_grant_type` | `/auth/token` does not implement the requested grant |
| `400` | `unsupported_token_type` | `/auth/revoke` received a valid access token but access-token denylisting is disabled |
| `400` | `invalid_scope` | Requested scope is unknown or exceeds the registered client ceiling |
| `400` | `unsupported_response_type` | `/auth/authorize` supports only `code` |
| `401` | `invalid_client` | Client is missing where required, unknown, or not authorised |

## JAFAAL extension and bearer errors

JAFAAL extension routes such as login, MFA, password, passkey, signup, session,
and API-key management use domain errors with a stable `code`:

```json
{ "detail": "The token is invalid.", "code": "invalid_token" }
```

FastAPI request-schema failures on these non-OAuth routes may use its native
HTTP `422` detail array. They are distinct from `JafaalError` domain failures
and from the OAuth contract above.

| Status | JAFAAL code or condition | Client action |
|---|---|---|
| `401` | `invalid_token` — expired or invalid access token | Refresh once, retry once |
| `401` | `password_change_required` — the password is correct but was set by an operator | Send the user to a password-change flow; retrying is futile |
| `403` | `insufficient_scope` | Do not retry; the grant is too narrow |
| `404` | Unknown resource | — |
| `429` | Rate limited or progressive lockout | Respect `Retry-After` |
| `503` | Auth state store unavailable | Retry with backoff |

Bearer failures carry a `WWW-Authenticate` challenge (RFC 6750).

## Polling sign-up confirmation

When email verification is required, every successful
`POST /auth/sign-up/request` response includes a 256-bit `signup_handle`. Keep
that handle in the waiting client and poll
`GET /auth/sign-up/status?handle=<signup_handle>` no more often than every five
seconds. The response is exactly `{"confirmed": false}` until the emailed token
is confirmed, then `{"confirmed": true}`. Unknown and expired handles return
`404`; handles expire with the sign-up token after 24 hours.

The handle is not a credential. It can only read this boolean; confirming the
account still requires the separate token delivered by email. JAFAAL also
returns a fresh decoy handle when the username or email already exists. That
handle remains `false`, so neither the presence of the field nor the initial
status reveals whether an account was created.

The route uses the distinct `polling` rate-limit category, whose built-in
budget is `30/minute`, and sends `Cache-Control: no-store`. Hosts with a custom
`RateLimiter` must map that category to a bounded polling budget. Handles live
in the configured `StateStore`; multi-worker or replicated deployments must
use a shared backend such as `RedisStateStore` so any worker can answer a poll.

## Other endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST`/`GET` | `/auth/sign-up/request` · `/auth/sign-up/confirm` · `/auth/sign-up/status` | Enumeration-safe sign-up and confirmation polling |
| `POST` | `/auth/password-reset/request` · `/auth/password-reset/confirm` | Enumeration-safe reset |
| `GET`/`DELETE` | `/auth/sessions/user/{user_id}` | List / revoke the user's sessions |
| `DELETE` | `/auth/sessions/{session_id}/user/{user_id}` | Revoke one session |
| `GET`/`POST` | `/auth/api-keys` | List / create API keys |
| `PATCH`/`DELETE` | `/auth/api-keys/{api_key_id}/revoke` · `/{api_key_id}` | Revoke / delete |
| `POST` | `/auth/webauthn/register/begin` · `/register/complete` | Passkey enrolment |
| `POST` | `/auth/webauthn/mfa/begin` · `/mfa/complete` | Passkey as second factor |
| `POST` | `/public/webauthn/authenticate/begin` · `/authenticate/complete` | Passwordless login |
| `GET` | `/public/idp` | Identity providers a client may offer |
| `GET` | `/public/idp/callback/{idp_slug}` | SSO callback |
| `POST` | `/auth/idp/step-up/reauth/{idp_id}` | Step-up re-authentication for SSO-only accounts |
