from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr
    name: str
    picture: Optional[str] = None


class UserCreate(UserBase):
    google_id: str


class UserResponse(UserBase):
    id: int
    google_id: str
    created_at: datetime
    last_access: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ApplicationResponse(BaseModel):
    id: int
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class JWKResponse(BaseModel):
    kty: str
    kid: str
    use: str = "sig"
    alg: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    keys: list[JWKResponse]


class DeniedAppBase(BaseModel):
    app_name: str


class DeniedAppCreate(DeniedAppBase):
    pass


class DeniedAppResponse(DeniedAppBase):
    id: int
    user_id: int
    denied_at: datetime
    denied_by: Optional[str] = None

    model_config = {"from_attributes": True}


class AllowedAppsResponse(BaseModel):
    email: str
    denied_apps: list[str]
    allowed_apps: list[str]


class AccessTokenPayload(BaseModel):
    sub: str
    email: str
    app_name: Optional[str] = None
    type: str = "access"
    exp: datetime


class RefreshTokenPayload(BaseModel):
    sub: str
    type: str = "refresh"
    exp: datetime
