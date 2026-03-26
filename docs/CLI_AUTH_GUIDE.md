# CLI Auth Guide

This guide is for CLI clients that send users through OrgAuth and receive tokens on a localhost callback.

If you are building an API, service, or backend that needs to validate or refresh OrgAuth-issued tokens, use `docs/APP_TOKEN_GUIDE.md` instead.

## Base URLs

| Environment | Base URL |
| --- | --- |
| Local | `http://localhost:8500` |
| Production | `https://auth.or-gm.com` |

## What the CLI Receives

After a successful login, OrgAuth gives the CLI:

- an access token JWT intended to last `15 minutes` and signed for JWKS-based downstream validation
- a refresh token JWT intended to last `7 days`
- basic user info

Current normalized token payload shape:

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": 123,
    "google_id": "google-user-id",
    "email": "user@or-gm.com",
    "name": "User Name",
    "picture": "https://...",
    "created_at": "2026-03-26T12:00:00",
    "last_access": "2026-03-26T12:00:00"
  }
}
```

## Login Flow

### 1. Start the browser flow

Send the user to:

```text
GET /auth?app_name=<registered-app-name>&redirect_uri=<client-callback-url>[&flow_id=<client-correlation-id>]
```

Example:

```text
GET /auth?app_name=orgmcalc-cli&redirect_uri=http://127.0.0.1:43123/callback&flow_id=login-42
```

Current behavior:

- `app_name` must exist in OrgAuth's applications table.
- `redirect_uri` is stored exactly as sent and reused after Google login finishes.
- `flow_id` is optional. If omitted, OrgAuth generates one and returns it on success.
- The OAuth flow expires after `10 minutes`.
- OrgAuth sends Google back to its own configured callback URL, then redirects from there to the CLI callback.

### 2. Listen on localhost for the callback

Run a temporary HTTP server on the callback URL you passed in `redirect_uri`.

Recommended CLI behavior:

- bind to `127.0.0.1` when possible
- listen only long enough to receive one callback
- stop listening immediately after capturing the query parameters
- avoid logging the full callback URL because it contains bearer tokens

### 3. Parse the callback query parameters

After Google login succeeds, OrgAuth redirects the browser to your `redirect_uri` with query parameters:

```text
GET <redirect_uri>?token=<access-token>&refresh_token=<refresh-token>&flow_id=<flow-id>&expires_in=900&user=<json-string>
```

Example callback query params:

```text
token=...
refresh_token=...
flow_id=login-42
expires_in=900
user={"id":123,"email":"user@or-gm.com","name":"User Name","picture":"https://..."}
```

Parameter meanings:

- `token`: the access token
- `refresh_token`: the refresh token
- `flow_id`: the original client correlation id, or the generated one if none was supplied
- `expires_in`: access token lifetime in seconds
- `user`: URL-encoded JSON containing `id`, `email`, `name`, and `picture`

Important caveats:

- The callback uses `token`, not `access_token`, for the access token query parameter.
- The callback `user` object is intentionally smaller than the full token response object.
- Tokens arrive in the URL query string, so browser history, local proxy logs, shell output, and analytics can leak them if you are not careful.

### 4. Optional helper for normalized JSON

If parsing the URL-encoded `user` JSON is inconvenient, OrgAuth exposes a helper endpoint that repackages the callback values into JSON:

```text
GET /callback/info?token=...&refresh_token=...&expires_in=900&user=...&flow_id=login-42
```

Response:

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "flow_id": "login-42",
  "expires_in": 900,
  "user": {
    "id": 123,
    "email": "user@or-gm.com",
    "name": "User Name",
    "picture": "https://..."
  }
}
```

Caveat:

- `GET /callback/info` only parses and returns the values you pass in. It is a convenience endpoint, not a validation step.

## Storing Tokens

Store both tokens after the callback succeeds.

Recommended order of preference:

1. OS credential storage or keychain
2. A local file with restrictive permissions such as `0600`

Recommended stored fields:

- access token
- refresh token
- `expires_in` or your own computed access-token expiry timestamp
- user identity fields needed for UX
- `flow_id` only if it helps correlate in-flight login attempts

Important caveats:

- Replace both stored tokens after every successful refresh.
- Do not keep using an older refresh token after rotation succeeds.
- There is no server endpoint that can recover a lost refresh token from an access token.
- Treat the refresh token as an OrgAuth-only exchange credential. Do not try to validate it locally with JWKS.

## When the CLI Must Send the User Through Login Again

Start a fresh `/auth` flow when:

- the refresh request returns any `401`
- the original OAuth flow expires before completion (`400 OAuth flow expired`)
- the callback state is reused (`400 OAuth flow already completed`)
- the callback state is invalid or unknown (`400 Invalid state parameter` or `400 Unknown OAuth flow`)
- OrgAuth rejects the account because the email is outside the allowed domain (`403`)
- OrgAuth denies access to the selected app (`403 Access to '<app>' has been denied for your account`)
- the CLI has lost the refresh token or cannot read its secure token store

## Recommended CLI Behavior

1. Start a temporary localhost listener.
2. Open the browser to `GET /auth?...`.
3. Capture `token`, `refresh_token`, `flow_id`, `expires_in`, and `user` from the callback.
4. Persist the token pair securely.
5. Use the access token until an API call fails or the token is near expiry.
6. Refresh once.
7. If refresh fails with `401`, clear local auth state and send the user through login again.

For refresh and token-consumption details, see `docs/APP_TOKEN_GUIDE.md`. New downstream integrations should validate access tokens with `/.well-known/jwks.json`; the CLI should still send refresh tokens only to `/token/refresh`.
