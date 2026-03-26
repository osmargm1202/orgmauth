# App Token Guide

This guide is for apps and services that consume OrgAuth-issued tokens after a user has already logged in.

If you are building the CLI login flow itself, including the localhost callback and token capture, use `docs/CLI_AUTH_GUIDE.md`.

## Base URLs

| Environment | Base URL |
| --- | --- |
| Local | `http://localhost:8500` |
| Production | `https://auth.or-gm.com` |

## What OrgAuth Issues

- Access token: JWT signed with `HS256`, intended lifetime `15 minutes`
- Refresh token: JWT signed with `HS256`, intended lifetime `7 days`

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

There are two practical options.

### Option A: Remote validation through OrgAuth

Current endpoint:

```text
GET /token/validate?authorization=Bearer%20<access-token>
```

Current success response:

```json
{
  "valid": true,
  "user": {
    "id": 123,
    "google_id": "google-user-id",
    "email": "user@or-gm.com",
    "name": "User Name",
    "picture": "https://...",
    "created_at": "2026-03-26T12:00:00",
    "last_access": "2026-03-26T12:00:00"
  },
  "expires_at": "2026-03-26T12:00:00"
}
```

Current invalid response:

```json
{
  "valid": false,
  "user": null,
  "expires_at": null
}
```

Recommended behavior:

- treat `valid: true` as "the token decoded, had `type=access`, and the user still exists"
- treat `valid: false` as unusable and refresh or reauthenticate
- cache successful validation briefly if you need to reduce calls back to OrgAuth

Current caveats:

- `/token/validate` reads `authorization` from the query string, not from the HTTP `Authorization` header
- `expires_at` is currently set to the server's current UTC time, not the token's real expiration time
- validation does not currently require the presented access token to match a stored session record

### Option B: Local JWT verification in a trusted service

Use local verification only if your service is trusted to hold the same signing secret as OrgAuth.

If you verify locally, enforce at least:

- signature verification with the shared `HS256` secret
- `type == "access"`
- `exp` has not passed

Treat `app_name` as context, not as a standalone authorization decision.

Current caveats:

- there is no JWKS endpoint
- there is no public key distribution model
- there is no standard token introspection endpoint
- desktop apps, distributed CLIs, and browser apps should not embed the OrgAuth signing secret just to verify tokens locally

## Refreshing Tokens

Current refresh endpoint:

```text
POST /token/refresh?refresh_token=<refresh-token>
```

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

Current caveat:

- `/token/refresh` expects `refresh_token` in the query string, not in a JSON or form body.

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
- do not schedule refreshes from `/token/validate.expires_at`; use the original `expires_in` or decode `exp` yourself
- prefer remote validation if your service should not know the OrgAuth signing secret
- return your own `401` or equivalent auth failure when OrgAuth validation fails

## Security and Implementation Caveats

- Access and refresh tokens are bearer credentials. Anyone holding them can act as the user until they expire or are revoked.
- Refresh token rotation is implemented: a successful refresh revokes the old session and returns a new refresh token.
- There is no endpoint that exchanges an access token for a new refresh token. If both tokens are unusable, the user must log in again.
- OrgAuth-protected endpoints inside this codebase use an actual `Authorization: Bearer <token>` header, but `/token/validate` itself currently does not.

## Minimal Integration Example

```python
import os
import httpx

AUTH_BASE = os.environ.get("ORGAUTH_BASE", "https://auth.or-gm.com")


def validate_access_token(access_token: str) -> bool:
    response = httpx.get(
        f"{AUTH_BASE}/token/validate",
        params={"authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    data = response.json()
    return response.status_code == 200 and data.get("valid") is True


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
