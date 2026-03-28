# App Token Guide

This guide is for apps and services that consume OrgAuth-issued tokens after a user has already logged in.

If you are building the CLI login flow itself, including the localhost callback and token capture, use `docs/CLI_AUTH_GUIDE.md`.

## Fetching the Live Guides from OrgAuth

The running service exposes the Markdown files under `docs/` through a safe read-only API:

- `GET /developer/docs` returns the list of published Markdown paths and fetch URLs.
- `GET /developer/docs/APP_TOKEN_GUIDE.md` returns this guide as `text/markdown`.
- `GET /developer/docs/CLI_AUTH_GUIDE.md` returns the CLI guide as `text/markdown`.

The path after `/developer/docs/` must match a real Markdown file under the service's `docs/` directory. Arbitrary filesystem paths are not exposed.

## Base URLs

| Environment | Base URL |
| --- | --- |
| Local | `http://localhost:8500` |
| Production | `https://auth.or-gm.com` |

## What OrgAuth Issues

- Access token: JWT signed with `RS256`, intended lifetime `15 minutes`
- Refresh token: JWT signed with `RS256` (same RSA keyring as access token), intended lifetime `7 days`

Current access token claims:

```json
{
  "sub": "123",
  "email": "user@or-gm.com",
  "app_name": "orgmcalc-cli",
  "type": "access",
  "exp": 1711459200
}
```

Current refresh token claims:

```json
{
  "sub": "123",
  "type": "refresh",
  "exp": 1711977600
}
```

## Validating Access Tokens

### Preferred option: local validation with JWKS

Fetch the public signing keys from:

```text
GET /.well-known/jwks.json
```

Access tokens now include a `kid` header so downstream services can pick the correct public key from the JWKS response and validate them locally with standard JWT tooling.

Expected access-token claims:

```json
{
  "sub": "123",
  "email": "user@or-gm.com",
  "app_name": "orgmcalc-cli",
  "type": "access",
  "exp": 1711459200
}
```

Recommended validator behavior:

- cache `/.well-known/jwks.json` using the response cache headers
- validate signature, `exp`, and `type == "access"`
- if the token `kid` is unknown, refresh JWKS once and retry
- if the `kid` is still unknown after refresh, treat the token as invalid

Example using PyJWT:

```python
import requests
import jwt

AUTH_BASE = "https://auth.or-gm.com"


def validate_access_token(access_token: str) -> dict:
    jwks = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=10).json()
    header = jwt.get_unverified_header(access_token)
    jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    return jwt.decode(access_token, public_key, algorithms=["RS256"])
```

## Refreshing Tokens

Current refresh endpoint:

```text
POST /token/refresh?refresh_token=<refresh-token>
```

Request notes:

- `refresh_token` is required and is currently passed in the query string.
- A successful refresh always rotates the refresh token; store the returned replacement immediately.
- The returned access token is a new RS256 JWT for downstream bearer auth.

Current success response:

```json
{
  "access_token": "<new-access-token>",
  "refresh_token": "<new-refresh-token>",
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

Response field shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `access_token` | `string` | New bearer access token to send to downstream APIs. |
| `refresh_token` | `string` | New rotated refresh token that replaces the old one. |
| `token_type` | `string` | Always `bearer`. |
| `expires_in` | `integer` | Access-token lifetime in seconds. |
| `user.id` | `integer` | OrgAuth user id. |
| `user.google_id` | `string` | Backing Google account identifier. |
| `user.email` | `string` | User email. |
| `user.name` | `string` | Display name. |
| `user.picture` | `string \| null` | Avatar URL when available. |
| `user.created_at` | `string` | User creation timestamp in ISO-like datetime format. |
| `user.last_access` | `string \| null` | Most recent recorded access timestamp. |

Example `200 OK` flow:

1. Client sends `POST /token/refresh?refresh_token=<current-refresh-token>`.
2. OrgAuth verifies the refresh token against its session state.
3. OrgAuth responds with the JSON object above.
4. Client replaces both the stored access token and stored refresh token with the returned values.

Current failure cases:

- `401 Invalid refresh token`
- `401 Session not found`
- `401 Refresh token expired`
- `401 User not found`
- `422` when `refresh_token` is omitted

Recommended behavior:

1. Refresh when an API call fails because the access token is invalid or expired, or shortly before the access token should expire.
2. Replace both stored tokens after every successful refresh.
3. Never continue using the old refresh token after a successful refresh.
4. If refresh returns any `401`, clear local auth state and start a new login.

Refresh contract notes:

- `/token/refresh` still expects `refresh_token` in the query string
- a successful refresh returns a new asymmetric access token and a rotated refresh token
- refresh tokens are OrgAuth-only credentials and are not published in JWKS

## When to Reauthenticate

Start a fresh login flow when:

- refresh returns any `401`
- both tokens are missing or unreadable from secure storage
- the user explicitly signs out or switches accounts
- the original login flow expired or was rejected before tokens were issued

In practice, clients should follow this order:

1. Try the stored access token.
2. If the target service or OrgAuth rejects it, try one refresh.
3. If refresh fails, send the user through login again.

## Recommended Client Behavior

- keep the access token in memory when possible and persist the refresh token in secure storage
- rotate the stored token pair atomically after a successful refresh so the process never keeps a stale refresh token
- do not rely on OrgAuth to validate access tokens request-by-request; use the original `expires_in` or decode `exp` yourself
- return your own `401` or equivalent auth failure when OrgAuth validation fails

## Security and Implementation Caveats

- Access and refresh tokens are bearer credentials. Anyone holding them can act as the user until they expire or are revoked.
- Refresh token rotation is implemented: a successful refresh revokes the old session and returns a new refresh token.
- There is no endpoint that exchanges an access token for a new refresh token. If both tokens are unusable, the user must log in again.
- Legacy HS256 access tokens without `kid` may still validate inside OrgAuth during a short rollout window while older tokens age out.

## Minimal Integration Example

```python
import httpx

AUTH_BASE = "https://auth.or-gm.com"


def refresh_session(refresh_token: str) -> dict | None:
    response = httpx.post(
        f"{AUTH_BASE}/token/refresh",
        params={"refresh_token": refresh_token},
        timeout=10,
    )
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return None
    response.raise_for_status()
```
