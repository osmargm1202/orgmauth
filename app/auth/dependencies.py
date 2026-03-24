from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Session as SessionModel
from app.auth.jwt import verify_access_token, verify_token_hash
from app.schemas import AccessTokenPayload, UserResponse

security = HTTPBearer(auto_error=False)


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if credentials is None:
        return None

    token_payload = verify_access_token(credentials.credentials)
    if token_payload is None:
        return None

    user = db.query(User).filter(User.id == token_payload.sub).first()
    if user is None:
        return None

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user.id,
            SessionModel.revoked == False,
        )
        .first()
    )

    if session and session.expires_at < session.expires_at.utcnow():
        return None

    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )

    token_payload = verify_access_token(credentials.credentials)
    if token_payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(User).filter(User.id == token_payload.sub).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user.id,
            SessionModel.revoked == False,
        )
        .order_by(SessionModel.created_at.desc())
        .first()
    )

    if session and session.expires_at < session.expires_at.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    return user
