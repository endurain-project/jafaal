# Mobile client walkthrough

How a native app drives JAFAAL. Runs against [minimal_app/app.py](minimal_app/app.py)
with the `example-mobile` client, registered with `token_delivery="body"` and the
redirect URI `com.example.app:/callback`.

## Which flow to use

JAFAAL offers two ways for a native app to authenticate. **Prefer the first.**

| | `/auth/authorize` + `/auth/token` | `/auth/login` |
|---|---|---|
| Where the password is typed | The system browser | Your app's UI |
| App ever sees the password | **No** | Yes |
| RFC 8252 §8.1 | Conformant | Not conformant |
| Use when | Always, if you can | You fully own and trust the client, and cannot open a browser |

The authorization-code flow keeps the password out of your process entirely. It
is also what any off-the-shelf OAuth library already speaks, so you should not be
hand-rolling any of this — use AppAuth (iOS/Android) or your platform's
equivalent and point it at the discovery document.

## 0. Discover the endpoints

```http
GET /.well-known/oauth-authorization-server
```

Everything needed to drive JAFAAL is a standard RFC 8414 field. Do not hard-code
endpoint URLs.

## 1. Generate a PKCE pair

PKCE is **mandatory** — there is no way to disable it, and `plain` is refused.

```
code_verifier  = base64url(random 32 bytes)      # 43-128 chars, [A-Za-z0-9-._~]
code_challenge = base64url(SHA256(code_verifier))
```

Keep the verifier in memory. It never leaves the app, which is exactly what makes
an intercepted authorization code useless.

## 2. Open the system browser

Use `ASWebAuthenticationSession` (iOS) or Custom Tabs (Android) — **not** a
WebView. The system browser shows the address bar (so the user can see they are
on the real domain) and runs in an isolated process your app cannot read.

```
GET /api/v1/auth/authorize
  ?response_type=code
  &client_id=example-mobile
  &redirect_uri=com.example.app%3A%2Fcallback
  &code_challenge=<challenge>
  &code_challenge_method=S256
  &state=<random>
  &scope=profile
```

`redirect_uri` must match a registered URI **byte for byte**. Add `&idp=<slug>`
to authenticate against an identity provider instead of a local password.

What happens next depends on `idp`:

- **omitted** — JAFAAL parks the validated request and redirects the browser to
  the host's `login_ui_url` with an `auth_request` handle. That page collects the
  password (and MFA, or a passkey) and posts to `/auth/login` with the handle.
- **present** — the browser goes to the identity provider, and its callback
  issues the code.

Either way, nothing about the grant is re-read from the login page: client,
redirect URI, PKCE challenge and scope all come from the parked request, so a
compromised login page cannot widen or redirect the grant. **No token ever
appears in a redirect** — only a single-use code.

## 3. Receive the code

The browser redirects to your registered scheme:

```
com.example.app:/callback?code=<code>&state=<state>&iss=http%3A%2F%2F127.0.0.1%3A8000
```

Before doing anything else:

- **Check `state`** matches the value you sent. Discard the response if not.
- **Check `iss`** matches the issuer from the discovery document (RFC 9207) — this
  is what stops a mix-up attack when your app talks to more than one provider.

## 4. Redeem the code

```http
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&code_verifier=<verifier>
&client_id=example-mobile
&redirect_uri=com.example.app:/callback
```

```json
{
  "session_id": "…",
  "access_token": "eyJ…",
  "refresh_token": "eyJ…",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token_expires_in": 604800,
  "scope": "profile"
}
```

Four bindings must all hold or the code is refused: PKCE, `client_id`,
byte-exact `redirect_uri`, and single use. Every failure returns the same
`invalid_grant`, so the endpoint cannot be used to probe which codes or clients
exist — do not try to branch on the reason.

The code is single-use. Redeeming one twice past a short grace window is treated
as theft and revokes the tokens it issued.

## 5. Store the tokens

| Platform | Use |
|---|---|
| iOS | Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| Android | `EncryptedSharedPreferences` or the Keystore |

Never `UserDefaults`, `SharedPreferences`, or a file in the app bundle.

## 6. Call the API

```http
GET /api/v1/me
Authorization: Bearer <access_token>
```

Mobile clients send no CSRF token — there is no ambient cookie to protect.

## 7. Refresh

```http
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>&client_id=example-mobile
```

Every refresh **rotates** the refresh token. Persist the new one before you use
it, and keep exactly one refresh in flight — if a background upload and a
foreground request both refresh at once, the loser presents a superseded token.

There is a 60-second grace window so a lost response can be retried safely.
Past it, reuse invalidates the entire token family and every session from that
login is revoked. If a refresh fails, do not retry with the old token: discard
the credentials and send the user back through step 2.

## 8. Log out

```http
POST /api/v1/auth/logout
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <refresh_token>

client_id=example-mobile
```

Then delete both tokens from the keystore. To revoke without a full logout, use
`/auth/revoke` (RFC 7009).

## The direct-login alternative

If you genuinely cannot open a browser, `/auth/login` authenticates a first-party
user directly:

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=demo&password=correct-horse-battery-staple&client_id=example-mobile
```

This returns `refresh_token` in the body because the client is registered with
`token_delivery="body"`.

> [!IMPORTANT]
> This is **not** the resource-owner password-credentials grant, which OAuth 2.1
> removes — it is a first-party API for an app that owns both the login form and
> the user directory, and it is deliberately not advertised in the discovery
> document. Your app handles the user's password, which is precisely what step 2
> avoids. Use it only if you accept that trade.

MFA works the same as on the web: a `202` challenge carrying a single-use
`mfa_token`, completed at `/auth/mfa/verify` with `mfa_token`, `mfa_code` and
`client_id`.

## Checklist

- [ ] System browser, never a WebView
- [ ] Fresh PKCE verifier per authorization request
- [ ] `state` and `iss` both validated on the callback
- [ ] Tokens in the platform keystore only
- [ ] One in-flight refresh; persist the rotated token before use
- [ ] Refresh failure → full re-authentication, never a retry with the old token
- [ ] Custom scheme registered and unique to your app
