# Web client walkthrough

How a browser application drives JAFAAL. Everything below runs against
[minimal_app/app.py](minimal_app/app.py) with the `example-web` client, which is
registered with `token_delivery="cookie"`.

## The storage model

This is the part worth getting right, so start here.

| Credential | Where it lives | Lifetime | Why |
|---|---|---|---|
| Access token | **JavaScript memory only** | 15 min | Never persisted, so XSS cannot exfiltrate it from storage and a stolen one expires fast |
| Refresh token | **`HttpOnly` cookie** (`jafaal_refresh_token`) | 7 days | Page script cannot read it at all (RFC 9700 §7.2). Shared across tabs |
| CSRF token | **JavaScript memory only** | Session | Proves a state-changing request came from your code, not a cross-site form |

Do **not** put the access token in `localStorage` or `sessionStorage`. Anything
script can read, injected script can read.

The cookie is `HttpOnly`, `SameSite=Strict`, scoped to the auth path, and
`Secure` whenever `environment` is a deployed value. On local IP loopback the example
uses `environment="development"` so the cookie survives plain HTTP.

## 1. Log in

`client_id` is required. The registration — not this request — decides that the
refresh token comes back as a cookie.

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=demo&password=correct-horse-battery-staple&client_id=example-web
```

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

Plus `Set-Cookie: jafaal_refresh_token=…; HttpOnly; SameSite=Strict`. Notice
there is no `refresh_token` field — that is the point.

```js
const res = await fetch("/api/v1/auth/login", {
  method: "POST",
  credentials: "include",              // required, or the cookie is dropped
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ username, password, client_id: "example-web" }),
});
const { access_token, csrf_token } = await res.json();
// Keep both in a module-scoped variable. Never in localStorage.
```

`scope` tells you what the token actually carries, which may be narrower than
you asked for. Drive your UI off that, not off assumptions.

## 2. Call a protected endpoint

```js
await fetch("/api/v1/me", {
  headers: { Authorization: `Bearer ${accessToken}` },
  credentials: "include",
});
```

For state-changing requests (`POST`/`PUT`/`PATCH`/`DELETE`) add the CSRF header:

```js
headers: {
  Authorization: `Bearer ${accessToken}`,
  "X-CSRF-Token": csrfToken,
}
```

## 3. Refresh

The cookie is sent automatically. Refresh proactively — at ~80% of `expires_in`
— rather than waiting for a 401.

```js
const res = await fetch("/api/v1/auth/refresh", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    "X-CSRF-Token": csrfToken,        // omit only on the reload bootstrap below
  },
  body: new URLSearchParams({ client_id: "example-web" }),
});
```

Every refresh **rotates** the token. Presenting a superseded one after a short
grace window is treated as theft and invalidates the whole token family — every
session from that login is revoked at once. Two consequences for your client:

- **Serialize refreshes.** If three requests 401 at the same time and each fires
  its own refresh, the later ones present a rotated token. Use a single in-flight
  refresh promise that all callers await.
- **Store the new `csrf_token`** from the response; the previous one is stale.

## 4. Survive a page reload

On reload the in-memory access and CSRF tokens are gone, but the `HttpOnly`
cookie is still there. Call refresh **without** the `X-CSRF-Token` header to
bootstrap a new pair:

```js
// On app init, before rendering anything that needs auth.
const res = await fetch("/api/v1/auth/refresh", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ client_id: "example-web" }),
});
if (res.ok) { /* restore tokens */ } else { /* show the login screen */ }
```

This bootstrap is safe because JAFAAL independently rejects off-site requests
using `Origin` and `Sec-Fetch-Site`, which are forbidden header names — page
script cannot forge or strip them, unlike a custom header a cross-site attacker
would simply omit. If you *do* send `X-CSRF-Token`, it must be valid.

## 5. Multi-factor authentication

When MFA is enabled, `/auth/login` answers with a challenge instead of tokens:

```json
{
  "mfa_required": true,
  "mfa_token": "…",
  "username": "demo",
  "message": "MFA verification required"
}
```

`mfa_token` is a single-use, five-minute ticket proving the password factor was
satisfied **by this caller**. Hold it in memory and never persist it. `username`
is echoed back for display only — it is not a credential.

```http
POST /api/v1/auth/mfa/verify
Content-Type: application/json

{ "mfa_token": "…", "mfa_code": "123456", "client_id": "example-web" }
```

`mfa_code` accepts a TOTP code or a single-use backup code (`XXXX-XXXX`). The
response is the same token bundle as a direct login. For passkeys as a second
factor, use `/auth/webauthn/mfa/begin` and `/auth/webauthn/mfa/complete` instead.

## 6. Log out

```js
await fetch("/api/v1/auth/logout", {
  method: "POST",
  credentials: "include",
  headers: { "X-CSRF-Token": csrfToken },
  body: new URLSearchParams({ client_id: "example-web" }),
});
```

The server deletes the session and clears the cookie. Drop your in-memory tokens.

## Errors worth handling

| Status | Meaning | Do |
|---|---|---|
| `401` | Access token expired or invalid | Refresh once, retry once, then log out |
| `401` after refresh | Refresh token revoked, expired, or **reused** | Send the user to the login screen — the family may have been invalidated |
| `403` `insufficient_scope` | Token lacks a required scope | Do not retry; the grant is too narrow |
| `429` | Rate limited or account locked out | Respect `Retry-After` |

Failures use the RFC 6749 §5.2 shape (`{"error", "error_description"}`) on the
OAuth endpoints, so a standard client library parses them without special-casing.

## Checklist

- [ ] Access and CSRF tokens in memory only, never `localStorage`
- [ ] `credentials: "include"` on every auth call
- [ ] One in-flight refresh, shared by all callers
- [ ] Bootstrap refresh on app init to survive reload
- [ ] Store the new `csrf_token` after every refresh
- [ ] `X-CSRF-Token` on every state-changing request
- [ ] HTTPS and `environment="production"` in production
