from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    User,
    Session as SessionModel,
    UserDeniedApp,
    Application,
    AccessLog,
)
from app.auth.dependencies import get_current_user
from app.auth.jwt import (
    verify_access_token,
    verify_refresh_token,
    create_access_token,
    create_refresh_token,
    hash_token,
    verify_token_hash,
)
from app.config import settings
from app.schemas import (
    UserResponse,
    TokenResponse,
    DeniedAppCreate,
    DeniedAppResponse,
)

router = APIRouter(prefix="/token", tags=["protected"])


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db),
):
    token_payload = verify_refresh_token(refresh_token)
    if token_payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    hashed_refresh_token = hash_token(refresh_token)
    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == int(token_payload.sub),
            SessionModel.revoked == False,
            SessionModel.refresh_token_hash == hashed_refresh_token,
        )
        .order_by(SessionModel.created_at.desc())
        .first()
    )

    if session is None:
        candidate_sessions = (
            db.query(SessionModel)
            .filter(
                SessionModel.user_id == int(token_payload.sub),
                SessionModel.revoked == False,
            )
            .order_by(SessionModel.created_at.desc())
            .all()
        )
        session = next(
            (
                candidate
                for candidate in candidate_sessions
                if verify_token_hash(refresh_token, candidate.refresh_token_hash)
            ),
            None,
        )

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )

    if not verify_token_hash(refresh_token, session.refresh_token_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if session.expires_at < datetime.utcnow():
        session.revoked = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    user = db.query(User).filter(User.id == int(token_payload.sub)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    session.revoked = True
    db.commit()

    access_token, _ = create_access_token(user.id, user.email, session.app_name)
    new_refresh_token, refresh_expires = create_refresh_token(user.id)

    new_session = SessionModel(
        user_id=user.id,
        refresh_token_hash=hash_token(new_refresh_token),
        access_token_hash=hash_token(access_token),
        app_name=session.app_name,
        expires_at=refresh_expires,
    )
    db.add(new_session)
    db.commit()

    user_response = UserResponse.model_validate(user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response,
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


@router.get("/denied-apps", response_model=list[DeniedAppResponse])
def list_denied_apps(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    denied = (
        db.query(UserDeniedApp)
        .filter(UserDeniedApp.user_id == current_user.id)
        .order_by(UserDeniedApp.denied_at.desc())
        .all()
    )
    return denied


@router.post("/denied-apps", response_model=DeniedAppResponse)
def add_denied_app(
    app: DeniedAppCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    app_exists = db.query(Application).filter(Application.name == app.app_name).first()
    if app_exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application '{app.app_name}' not found",
        )

    existing = (
        db.query(UserDeniedApp)
        .filter(
            UserDeniedApp.user_id == current_user.id,
            UserDeniedApp.app_name == app.app_name,
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application '{app.app_name}' is already denied for this user",
        )

    denied_app = UserDeniedApp(
        user_id=current_user.id,
        app_name=app.app_name,
        denied_by=current_user.email,
    )
    db.add(denied_app)
    db.commit()
    db.refresh(denied_app)

    return denied_app


@router.delete("/denied-apps/{app_name}")
def remove_denied_app(
    app_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    denied_app = (
        db.query(UserDeniedApp)
        .filter(
            UserDeniedApp.user_id == current_user.id,
            UserDeniedApp.app_name == app_name,
        )
        .first()
    )

    if denied_app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application '{app_name}' is not in the denied list",
        )

    db.delete(denied_app)
    db.commit()

    return {"message": f"Application '{app_name}' has been removed from denied list"}
