import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from tests.key_material import (
    TEST_ACCESS_TOKEN_PRIVATE_KEY,
    TEST_ACCESS_TOKEN_PUBLIC_KEY,
)


TEST_DB_PATH = Path(__file__).resolve().parent / "test_oauth_flow.db"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-client-secret")
os.environ.setdefault("ACCESS_TOKEN_ACTIVE_KID", "test-rs256-key")
os.environ.setdefault("ACCESS_TOKEN_PRIVATE_KEY_PEM", TEST_ACCESS_TOKEN_PRIVATE_KEY)
os.environ.setdefault("ACCESS_TOKEN_PUBLIC_KEY_PEM", TEST_ACCESS_TOKEN_PUBLIC_KEY)

from app.auth.jwt import (
    create_access_token,
    get_access_token_keyring,
    load_access_token_keyring,
)
from app.config import AccessTokenKeyringConfig
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import Session as SessionModel, User


@pytest.fixture()
def db_session():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    from app.database import get_db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _create_user_and_session(db_session):
    user = User(
        google_id="google-user-validate",
        email="person@or-gm.com",
        name="Validate User",
        picture=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    access_token, access_expires = create_access_token(
        user_id=user.id,
        email=user.email,
        app_name="orgmcalc-cli",
    )
    session = SessionModel(
        user_id=user.id,
        refresh_token_hash="unused",
        access_token_hash="unused",
        app_name="orgmcalc-cli",
        expires_at=access_expires,
    )
    db_session.add(session)
    db_session.commit()
    return user, access_token


def test_load_access_token_keyring_rejects_duplicate_kids():
    with pytest.raises(ValueError, match="duplicate"):
        load_access_token_keyring(
            AccessTokenKeyringConfig(
                active_kid="dup",
                keys=[
                    {
                        "kid": "dup",
                        "algorithm": "RS256",
                        "public_key_pem": (
                            get_access_token_keyring().active_key.public_key_pem
                        ),
                        "private_key_pem": (
                            get_access_token_keyring().active_key.private_key_pem
                        ),
                        "status": "active",
                    },
                    {
                        "kid": "dup",
                        "algorithm": "RS256",
                        "public_key_pem": (
                            get_access_token_keyring().active_key.public_key_pem
                        ),
                        "status": "grace",
                    },
                ],
            )
        )


def test_load_access_token_keyring_rejects_retired_active_key():
    with pytest.raises(ValueError, match="retired"):
        load_access_token_keyring(
            AccessTokenKeyringConfig(
                active_kid="retired",
                keys=[
                    {
                        "kid": "retired",
                        "algorithm": "RS256",
                        "public_key_pem": (
                            get_access_token_keyring().active_key.public_key_pem
                        ),
                        "private_key_pem": (
                            get_access_token_keyring().active_key.private_key_pem
                        ),
                        "status": "retired",
                    }
                ],
            )
        )


def test_load_access_token_keyring_accepts_realistic_env_pem_formats():
    flattened_public_key = (
        "  '" + " ".join(TEST_ACCESS_TOKEN_PUBLIC_KEY.splitlines()) + "'  "
    )
    escaped_private_key = (
        '  "' + TEST_ACCESS_TOKEN_PRIVATE_KEY.replace("\n", "\\n") + '"  '
    )

    keyring = load_access_token_keyring(
        AccessTokenKeyringConfig(
            active_kid="env-format-key",
            keys=[
                {
                    "kid": "env-format-key",
                    "algorithm": "RS256",
                    "public_key_pem": flattened_public_key,
                    "private_key_pem": escaped_private_key,
                    "status": "active",
                }
            ],
        )
    )

    assert keyring.active_key.kid == "env-format-key"
    assert keyring.active_key.public_key_pem == TEST_ACCESS_TOKEN_PUBLIC_KEY
    assert keyring.active_key.private_key_pem == TEST_ACCESS_TOKEN_PRIVATE_KEY


def test_jwks_endpoint_exposes_active_public_key(client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300, must-revalidate"

    payload = response.json()
    assert len(payload["keys"]) == 1
    assert payload["keys"][0]["kty"] == "RSA"
    assert payload["keys"][0]["kid"] == "test-rs256-key"
    assert payload["keys"][0]["use"] == "sig"
    assert payload["keys"][0]["alg"] == "RS256"
    assert payload["keys"][0]["e"] == "AQAB"
    assert payload["keys"][0]["n"]


def test_protected_endpoint_accepts_valid_asymmetric_access_token(client, db_session):
    user, access_token = _create_user_and_session(db_session)

    response = client.get(
        "/token/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == user.id
    assert payload["email"] == user.email


def test_protected_endpoint_rejects_unknown_kid_token(client, db_session):
    user = User(
        google_id="google-user-unknown-kid",
        email="unknown@or-gm.com",
        name="Unknown Kid",
        picture=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    session = SessionModel(
        user_id=user.id,
        refresh_token_hash="unused",
        access_token_hash="unused",
        app_name="orgmcalc-cli",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    db_session.add(session)
    db_session.commit()

    active_key = get_access_token_keyring().active_key
    token = jwt.encode(
        {
            "sub": str(user.id),
            "email": user.email,
            "app_name": "orgmcalc-cli",
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        },
        active_key.private_key_pem,
        algorithm="RS256",
        headers={"kid": "missing-key", "typ": "JWT", "alg": "RS256"},
    )

    response = client.get(
        "/token/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_legacy_hs256_access_tokens_still_work_for_protected_routes(
    client, db_session, monkeypatch
):
    user = User(
        google_id="google-user-legacy",
        email="legacy@or-gm.com",
        name="Legacy User",
        picture=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    session = SessionModel(
        user_id=user.id,
        refresh_token_hash="unused",
        access_token_hash="unused",
        app_name="orgmcalc-cli",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    db_session.add(session)
    db_session.commit()

    monkeypatch.setattr("app.config.settings.ORGM_SECRET_KEY", "test-secret-key")

    legacy_token = jwt.encode(
        {
            "sub": str(user.id),
            "email": user.email,
            "app_name": "orgmcalc-cli",
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        },
        "test-secret-key",
        algorithm="HS256",
    )

    response = client.get(
        "/token/me",
        headers={"Authorization": f"Bearer {legacy_token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == user.id
