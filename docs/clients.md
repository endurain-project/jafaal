# Client integration reference

The HTTP contract a client codes against: endpoints, wire formats, scopes, and
error semantics.

For step-by-step tutorials, see the runnable example and its walkthroughs:
[`examples/`](https://github.com/endurain-project/jafaal/tree/main/examples) —
[web](https://github.com/endurain-project/jafaal/blob/main/examples/web_client.md)
and
[mobile](https://github.com/endurain-project/jafaal/blob/main/examples/mobile_client.md).

Paths below are relative to wherever you mounted the router (the example mounts
it at `/api/v1`).

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
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414. Carries no extension members — everything needed to drive JAFAAL is a standard field |
| `GET` | `/.well-known/jwks.json` | RFC 7517. **404 under HS256**, which is correct: there is no public key, and `jwks_uri` is omitted from the metadata rather than serving an empty key set |

Do not hard-code endpoint URLs; read them from the metadata document.

## Authentication

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/auth/login` | form: `username`, `password`, `client_id`, optional `auth_request` | Token bundle, or a `202` MFA challenge |
| `POST` | `/auth/mfa/verify` | JSON: `mfa_token`, `mfa_code`, `client_id` | Token bundle |
| `POST` | `/auth/refresh` | form: `client_id` | Rotated token bundle |
| `POST` | `/auth/password/change` | JSON: `new_password`, `current_password`/`mfa_code` as applicable, optional `revoke_other_sessions` | `{"message", "revoked_sessions"}` |
| `POST` | `/auth/logout` | form: `client_id` | `{"message": "Logout successful"}` |

`/auth/login` is a **first-party** endpoint, not an OAuth grant. It is
deliberately not the resource-owner password-credentials grant (removed by
OAuth 2.1) and is not advertised in the discovery document.

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
| `POST` | `/auth/revoke` | RFC 7009; returns `200` even for unknown tokens |

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

## Errors

OAuth endpoints use the RFC 6749 §5.2 shape, so a standard client library parses
them unmodified:

```json
{ "error": "invalid_grant", "error_description": "…" }
```

| Status | Condition | Client action |
|---|---|---|
| `400` | `invalid_request`, `invalid_grant` | Do not retry unchanged |
| `401` | `invalid_token` — expired or invalid access token | Refresh once, retry once |
| `401` | `password_change_required` — the password is correct but was set by an operator | Send the user to a password-change flow; retrying is futile |
| `403` | `insufficient_scope` | Do not retry; the grant is too narrow |
| `404` | Unknown resource | — |
| `429` | Rate limited or progressive lockout | Respect `Retry-After` |
| `503` | Auth state store unavailable | Retry with backoff |

Bearer failures carry a `WWW-Authenticate` challenge (RFC 6750).

## Other endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/sign-up/request` · `/auth/sign-up/confirm` | Enumeration-safe sign-up |
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
