from datetime import datetime
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


@router.get("/auth")
async def auth(
    app_name: str,
    redirect_uri: str,
    db: Session = Depends(get_db),
):
    app = db.query(Application).filter(Application.name == app_name).first()
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application '{app_name}' not found",
        )

    state_data = {
        "app_name": app_name,
        "redirect_uri": redirect_uri,
    }

    import base64
    import json

    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

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
        import base64
        import json

        state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter",
        )

    app_name = state_data.get("app_name")
    redirect_uri = state_data.get("redirect_uri")

    if not app_name or not redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameters",
        )

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

    user.last_access = datetime.utcnow()
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

    db.commit()

    user_response = UserResponse.model_validate(user)

    token_response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response,
    )

    from urllib.parse import urlencode
    import json

    params = {
        "token": access_token,
        "refresh_token": refresh_token,
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
):
    import json

    user_data = json.loads(user)
    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "user": user_data,
    }
