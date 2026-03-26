
import httpx

from app.config import settings


GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class GoogleOAuthError(Exception):
    pass


async def exchange_code_for_tokens(code: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.callback_url,
                "grant_type": "authorization_code",
            },
        )
        if response.status_code != 200:
            raise GoogleOAuthError(f"Failed to exchange code: {response.text}")
        return response.json()


async def get_google_userinfo(access_token: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise GoogleOAuthError(f"Failed to get user info: {response.text}")
        return response.json()


def verify_email_domain(email: str) -> bool:
    domain = email.split("@")[-1]
    return domain == settings.ALLOWED_DOMAIN
