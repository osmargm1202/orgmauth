from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.auth.jwt import get_jwks
from app.database import get_db
from app.models import Application, User, UserDeniedApp
from app.schemas import (
    ApplicationResponse,
    UserResponse,
    AllowedAppsResponse,
    JWKSResponse,
)
from app.config import settings

router = APIRouter(tags=["public"])


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
def get_jwks_document(response: Response):
    response.headers["Cache-Control"] = settings.JWKS_CACHE_CONTROL
    return get_jwks()


@router.get("/apps", response_model=list[ApplicationResponse])
def list_applications(db: Session = Depends(get_db)):
    apps = db.query(Application).order_by(Application.name).all()
    return apps


@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users


@router.get("/users/{email}/allowed-apps", response_model=AllowedAppsResponse)
def get_user_allowed_apps(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    all_apps = db.query(Application.name).order_by(Application.name).all()
    all_app_names = [app.name for app in all_apps]

    denied = (
        db.query(UserDeniedApp.app_name).filter(UserDeniedApp.user_id == user.id).all()
    )
    denied_app_names = [d.app_name for d in denied]

    allowed_app_names = [app for app in all_app_names if app not in denied_app_names]

    return AllowedAppsResponse(
        email=email,
        denied_apps=denied_app_names,
        allowed_apps=allowed_app_names,
    )
