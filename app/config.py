import json
import re
from textwrap import wrap
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AccessTokenKeyConfig(BaseModel):
    kid: str
    algorithm: Literal["RS256"] = "RS256"
    public_key_pem: str
    private_key_pem: str | None = None
    status: Literal["active", "grace", "retired"] = "active"

    @field_validator("public_key_pem", "private_key_pem", mode="before")
    @classmethod
    def normalize_pem(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if (
            len(normalized) >= 2
            and normalized[0] == normalized[-1]
            and normalized[0] in {'"', "'"}
        ):
            normalized = normalized[1:-1].strip()

        normalized = normalized.replace("\\r\\n", "\n")
        normalized = normalized.replace("\\n", "\n")
        normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
        return _canonicalize_pem(normalized)


_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\s*"
    r"(?P<body>[A-Za-z0-9+/=\s]+?)\s*"
    r"-----END (?P=label)-----",
    re.DOTALL,
)


def _canonicalize_pem(value: str) -> str:
    collapsed = "\n".join(line.strip() for line in value.splitlines() if line.strip())
    match = _PEM_BLOCK_RE.fullmatch(collapsed)
    if not match:
        return collapsed.strip()

    label = match.group("label")
    body = "".join(match.group("body").split())
    wrapped_body = "\n".join(wrap(body, 64))
    return f"-----BEGIN {label}-----\n{wrapped_body}\n-----END {label}-----"


class AccessTokenKeyringConfig(BaseModel):
    active_kid: str
    keys: list[AccessTokenKeyConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_active_key(self) -> "AccessTokenKeyringConfig":
        if not self.keys:
            raise ValueError("access token keyring must include at least one key")

        keys_by_kid = {key.kid: key for key in self.keys}
        if len(keys_by_kid) != len(self.keys):
            raise ValueError("access token keyring contains duplicate kid values")

        active_key = keys_by_kid.get(self.active_kid)
        if active_key is None:
            raise ValueError("active_kid must reference a configured access-token key")
        if active_key.status == "retired":
            raise ValueError("active access-token key cannot be retired")
        if not active_key.private_key_pem:
            raise ValueError("active access-token key must include a private key")
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    ORGM_SECRET_KEY: str | None = None

    ALLOWED_DOMAIN: str = "or-gm.com"
    BASE_URL: str = "https://auth.or-gm.com"
    LOCAL_BASE_URL: str = "http://localhost:8500"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ACCESS_TOKEN_ACTIVE_KID: str
    ACCESS_TOKEN_ALGORITHM: Literal["RS256"] = "RS256"
    ACCESS_TOKEN_PUBLIC_KEY_PEM: str
    ACCESS_TOKEN_PRIVATE_KEY_PEM: str
    ACCESS_TOKEN_GRACE_KEYS_JSON: str = "[]"
    ACCESS_TOKEN_LEGACY_HS256_FALLBACK_ENABLED: bool = True
    ACCESS_TOKEN_LEGACY_FALLBACK_WINDOW_MINUTES: int = 15
    JWKS_CACHE_CONTROL: str = "public, max-age=300, must-revalidate"

    @property
    def access_token_keyring(self) -> AccessTokenKeyringConfig:
        grace_raw = self.ACCESS_TOKEN_GRACE_KEYS_JSON
        grace_keys = json.loads(grace_raw) if grace_raw else []
        return AccessTokenKeyringConfig.model_validate(
            {
                "active_kid": self.ACCESS_TOKEN_ACTIVE_KID,
                "keys": [
                    {
                        "kid": self.ACCESS_TOKEN_ACTIVE_KID,
                        "algorithm": self.ACCESS_TOKEN_ALGORITHM,
                        "public_key_pem": self.ACCESS_TOKEN_PUBLIC_KEY_PEM,
                        "private_key_pem": self.ACCESS_TOKEN_PRIVATE_KEY_PEM,
                        "status": "active",
                    },
                    *grace_keys,
                ],
            }
        )

    @property
    def auth_url(self) -> str:
        return f"{self.BASE_URL}/auth"

    @property
    def callback_url(self) -> str:
        return f"{self.BASE_URL}/callback"


settings = Settings()
