import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import AccessTokenKeyConfig, AccessTokenKeyringConfig, settings
from app.schemas import (
    AccessTokenPayload,
    JWKResponse,
    JWKSResponse,
    RefreshTokenPayload,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOKEN_HASH_PREFIX = "sha256:"
LEGACY_TOKEN_HASH_PREFIX = "hmac-sha256:"


@dataclass(frozen=True)
class AccessTokenKey:
    kid: str
    algorithm: str
    status: str
    public_key_pem: str
    private_key_pem: str | None

    def to_jwk(self) -> JWKResponse:
        public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(f"unsupported public key type for kid '{self.kid}'")

        numbers = public_key.public_numbers()
        return JWKResponse(
            kty="RSA",
            kid=self.kid,
            alg=self.algorithm,
            n=_b64url_uint(numbers.n),
            e=_b64url_uint(numbers.e),
        )


@dataclass(frozen=True)
class AccessTokenKeyring:
    active_kid: str
    keys_by_kid: dict[str, AccessTokenKey]

    @property
    def active_key(self) -> AccessTokenKey:
        return self.keys_by_kid[self.active_kid]

    def resolve_verification_key(self, kid: str) -> AccessTokenKey | None:
        key = self.keys_by_kid.get(kid)
        if key is None or key.status == "retired":
            return None
        return key

    def jwks(self) -> JWKSResponse:
        keys = [
            key.to_jwk()
            for key in self.keys_by_kid.values()
            if key.status in {"active", "grace"}
        ]
        keys.sort(key=lambda item: item.kid)
        return JWKSResponse(keys=keys)


def _b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(size, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def load_access_token_keyring(config: AccessTokenKeyringConfig) -> AccessTokenKeyring:
    keys_by_kid: dict[str, AccessTokenKey] = {}

    for key_config in config.keys:
        _validate_access_token_key_config(key_config)
        if key_config.kid in keys_by_kid:
            raise ValueError(f"duplicate access-token kid '{key_config.kid}'")
        keys_by_kid[key_config.kid] = AccessTokenKey(
            kid=key_config.kid,
            algorithm=key_config.algorithm,
            status=key_config.status,
            public_key_pem=key_config.public_key_pem,
            private_key_pem=key_config.private_key_pem,
        )

    keyring = AccessTokenKeyring(active_kid=config.active_kid, keys_by_kid=keys_by_kid)
    active_key = keyring.active_key
    if active_key.status == "retired":
        raise ValueError("active access-token key cannot be retired")
    if not active_key.private_key_pem:
        raise ValueError("active access-token key must include a private key")
    return keyring


def _validate_access_token_key_config(key_config: AccessTokenKeyConfig) -> None:
    try:
        public_key = serialization.load_pem_public_key(
            key_config.public_key_pem.encode()
        )
    except Exception as exc:  # pragma: no cover - exercised through tests
        raise ValueError(f"invalid public key for kid '{key_config.kid}'") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError(f"unsupported public key type for kid '{key_config.kid}'")

    if key_config.private_key_pem:
        try:
            private_key = serialization.load_pem_private_key(
                key_config.private_key_pem.encode(), password=None
            )
        except Exception as exc:  # pragma: no cover - exercised through tests
            raise ValueError(f"invalid private key for kid '{key_config.kid}'") from exc
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"unsupported private key type for kid '{key_config.kid}'")


ACCESS_TOKEN_KEYRING = load_access_token_keyring(settings.access_token_keyring)


def get_access_token_keyring() -> AccessTokenKeyring:
    return ACCESS_TOKEN_KEYRING


def get_jwks() -> JWKSResponse:
    return ACCESS_TOKEN_KEYRING.jwks()


def create_access_token(
    user_id: int, email: str, app_name: Optional[str] = None
) -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "email": email,
        "app_name": app_name,
        "type": "access",
        "exp": expires_at,
    }

    active_key = ACCESS_TOKEN_KEYRING.active_key
    token = jwt.encode(
        payload,
        active_key.private_key_pem,
        algorithm=active_key.algorithm,
        headers={"kid": active_key.kid, "typ": "JWT", "alg": active_key.algorithm},
    )
    return token, expires_at


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": secrets.token_urlsafe(16),
        "exp": expires_at,
    }
    active_key = ACCESS_TOKEN_KEYRING.active_key
    token = jwt.encode(
        payload,
        active_key.private_key_pem,
        algorithm=active_key.algorithm,
        headers={"kid": active_key.kid, "typ": "JWT", "alg": active_key.algorithm},
    )
    return token, expires_at


def decode_token(token: str) -> Optional[dict]:
    return decode_access_token(token)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return None

    kid = header.get("kid")
    if kid:
        verification_key = ACCESS_TOKEN_KEYRING.resolve_verification_key(kid)
        if verification_key is None:
            return None
        try:
            return jwt.decode(
                token,
                verification_key.public_key_pem,
                algorithms=[verification_key.algorithm],
            )
        except JWTError:
            return None

    if (
        not settings.ACCESS_TOKEN_LEGACY_HS256_FALLBACK_ENABLED
        or not settings.ORGM_SECRET_KEY
    ):
        return None

    try:
        return jwt.decode(token, settings.ORGM_SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        return None


def verify_access_token(token: str) -> Optional[AccessTokenPayload]:
    payload = decode_access_token(token)
    if payload is None:
        return None
    if payload.get("type") != "access":
        return None
    try:
        return AccessTokenPayload(**payload)
    except Exception:
        return None


def verify_refresh_token(token: str) -> Optional[RefreshTokenPayload]:
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return None

    kid = header.get("kid")
    if kid:
        verification_key = ACCESS_TOKEN_KEYRING.resolve_verification_key(kid)
        if verification_key is None:
            return None
        try:
            payload = jwt.decode(
                token,
                verification_key.public_key_pem,
                algorithms=[verification_key.algorithm],
            )
        except JWTError:
            return None
    elif settings.ORGM_SECRET_KEY:
        try:
            payload = jwt.decode(token, settings.ORGM_SECRET_KEY, algorithms=["HS256"])
        except JWTError:
            return None
    else:
        return None

    if payload.get("type") != "refresh":
        return None
    try:
        return RefreshTokenPayload(**payload)
    except Exception:
        return None


def hash_token(token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()
    return f"{TOKEN_HASH_PREFIX}{digest}"


def _legacy_hash_token(token: str) -> str:
    if not settings.ORGM_SECRET_KEY:
        raise ValueError("legacy token hashing requires ORGM_SECRET_KEY")
    digest = hmac.new(
        settings.ORGM_SECRET_KEY.encode(),
        token.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{LEGACY_TOKEN_HASH_PREFIX}{digest}"


def verify_token_hash(token: str, token_hash: str) -> bool:
    if token_hash.startswith(TOKEN_HASH_PREFIX):
        return hmac.compare_digest(hash_token(token), token_hash)
    if token_hash.startswith(LEGACY_TOKEN_HASH_PREFIX):
        if not settings.ORGM_SECRET_KEY:
            return False
        return hmac.compare_digest(_legacy_hash_token(token), token_hash)
    return pwd_context.verify(token, token_hash)
