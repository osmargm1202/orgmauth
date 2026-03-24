from datetime import datetime, timedelta
from typing import Optional

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings
from app.schemas import AccessTokenPayload, RefreshTokenPayload

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(
    user_id: int, email: str, app_name: Optional[str] = None
) -> tuple[str, datetime]:
    expires_at = datetime.utcnow() + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = AccessTokenPayload(
        sub=user_id, email=email, app_name=app_name, type="access"
    )
    token = jwt.encode(
        payload.model_dump(), settings.ORGM_SECRET_KEY, algorithm="HS256"
    )
    return token, expires_at


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = RefreshTokenPayload(sub=user_id, type="refresh")
    token = jwt.encode(
        payload.model_dump(), settings.ORGM_SECRET_KEY, algorithm="HS256"
    )
    return token, expires_at


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.ORGM_SECRET_KEY, algorithms=["HS256"])
        return payload
    except JWTError:
        return None


def verify_access_token(token: str) -> Optional[AccessTokenPayload]:
    payload = decode_token(token)
    if payload is None:
        return None
    if payload.get("type") != "access":
        return None
    try:
        return AccessTokenPayload(**payload)
    except Exception:
        return None


def verify_refresh_token(token: str) -> Optional[RefreshTokenPayload]:
    payload = decode_token(token)
    if payload is None:
        return None
    if payload.get("type") != "refresh":
        return None
    try:
        return RefreshTokenPayload(**payload)
    except Exception:
        return None


def hash_token(token: str) -> str:
    return pwd_context.hash(token)


def verify_token_hash(token: str, token_hash: str) -> bool:
    return pwd_context.verify(token, token_hash)
