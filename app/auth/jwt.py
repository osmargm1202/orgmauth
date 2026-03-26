import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings
from app.schemas import AccessTokenPayload, RefreshTokenPayload

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOKEN_HASH_PREFIX = "hmac-sha256:"


def create_access_token(
    user_id: int, email: str, app_name: Optional[str] = None
) -> tuple[str, datetime]:
    expires_at = datetime.utcnow() + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),  # jose requires sub to be string
        "email": email,
        "app_name": app_name,
        "type": "access",
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.ORGM_SECRET_KEY, algorithm="HS256")
    return token, expires_at


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),  # jose requires sub to be string
        "type": "refresh",
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.ORGM_SECRET_KEY, algorithm="HS256")
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
    digest = hmac.new(
        settings.ORGM_SECRET_KEY.encode(),
        token.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{TOKEN_HASH_PREFIX}{digest}"


def verify_token_hash(token: str, token_hash: str) -> bool:
    if token_hash.startswith(TOKEN_HASH_PREFIX):
        return hmac.compare_digest(hash_token(token), token_hash)
    return pwd_context.verify(token, token_hash)
