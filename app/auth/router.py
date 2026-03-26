import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import (
    User,
    Application,
    Session as SessionModel,
    AccessLog,
    UserDeniedApp,
    OAuthFlow,
)
from app.auth.google_oauth import (
    exchange_code_for_tokens,
    get_google_userinfo,
    verify_email_domain,
    GoogleOAuthError,
)
from app.auth.jwt import create_access_token, create_refresh_token, hash_token
from app.schemas import TokenResponse, UserResponse

router = APIRouter(prefix="", tags=["auth"])
OAUTH_FLOW_TTL = timedelta(minutes=10)


def _encode_state(state_id: str) -> str:
    state_data = {"sid": state_id}
    return base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()


def _decode_state(state: str) -> str:
    state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    state_id = state_data.get("sid")
    if not state_id:
        raise ValueError("Missing state id")
    return state_id


@router.get("/auth")
async def auth(
    app_name: str,
    redirect_uri: str,
    flow_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    app = db.query(Application).filter(Application.name == app_name).first()
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application '{app_name}' not found",
        )

    state_id = secrets.token_urlsafe(32)
    resolved_flow_id = flow_id or secrets.token_urlsafe(24)
    oauth_flow = OAuthFlow(
        state_id=state_id,
        flow_id=resolved_flow_id,
        app_name=app_name,
        redirect_uri=redirect_uri,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + OAUTH_FLOW_TTL,
    )
    db.add(oauth_flow)
    db.commit()

    state = _encode_state(state_id)

    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.callback_url,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }

    return RedirectResponse(f"{google_auth_url}?{urlencode(params)}")


@router.get("/callback")
async def callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
    request: Request = None,
):
    try:
        state_id = _decode_state(state)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter",
        )

    oauth_flow = db.query(OAuthFlow).filter(OAuthFlow.state_id == state_id).first()
    if oauth_flow is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown OAuth flow",
        )
    if oauth_flow.consumed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth flow already completed",
        )
    if oauth_flow.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth flow expired",
        )

    app_name = oauth_flow.app_name
    redirect_uri = oauth_flow.redirect_uri

    try:
        token_data = await exchange_code_for_tokens(code)
        google_user = await get_google_userinfo(token_data["access_token"])
    except GoogleOAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    email = google_user.get("email", "")
    if not verify_email_domain(email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Only {settings.ALLOWED_DOMAIN} emails are allowed",
        )

    user = db.query(User).filter(User.google_id == google_user["sub"]).first()
    if user is None:
        user = User(
            google_id=google_user["sub"],
            email=email,
            name=google_user.get("name", email.split("@")[0]),
            picture=google_user.get("picture"),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    user.last_access = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    denied = (
        db.query(UserDeniedApp)
        .filter(
            UserDeniedApp.user_id == user.id,
            UserDeniedApp.app_name == app_name,
        )
        .first()
    )
    if denied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access to '{app_name}' has been denied for your account",
        )

    access_token, access_expires = create_access_token(user.id, user.email, app_name)
    refresh_token, refresh_expires = create_refresh_token(user.id)

    session = SessionModel(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        access_token_hash=hash_token(access_token),
        app_name=app_name,
        expires_at=refresh_expires,
    )
    db.add(session)

    access_log = AccessLog(
        user_id=user.id,
        app_name=app_name,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
    )
    db.add(access_log)

    oauth_flow.consumed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.commit()

    user_response = UserResponse.model_validate(user)

    token_response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response,
    )

    params = {
        "token": access_token,
        "refresh_token": refresh_token,
        "flow_id": oauth_flow.flow_id,
        "expires_in": token_response.expires_in,
        "user": json.dumps(
            {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "picture": user.picture,
            }
        ),
    }

    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")


@router.get("/callback/info")
async def callback_info(
    token: str,
    refresh_token: str,
    expires_in: int,
    user: str,
    flow_id: Optional[str] = None,
):
    user_data = json.loads(user)
    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "flow_id": flow_id,
        "expires_in": expires_in,
        "user": user_data,
    }
