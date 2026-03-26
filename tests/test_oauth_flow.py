import base64
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from starlette.requests import Request


TEST_DB_PATH = Path(__file__).resolve().parent / "test_oauth_flow.db"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-client-secret")
os.environ.setdefault("ORGM_SECRET_KEY", "test-secret-key")

from app.auth import router as auth_router
from app.auth.jwt import create_refresh_token, hash_token, verify_token_hash
from app.database import Base, SessionLocal, engine
from app.models import Application, OAuthFlow, Session as SessionModel


def _extract_state(location: str) -> str:
    query = parse_qs(urlparse(location).query)
    return query["state"][0]


def _decode_state(state: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(state.encode()).decode())


def _build_request() -> Request:
    scope = {
        "type": "http",
        "headers": [(b"user-agent", b"pytest")],
        "client": ("127.0.0.1", 5000),
    }
    return Request(scope)


@pytest.fixture()
def db_session():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    db.add(Application(name="orgmcalc-cli"))
    db.commit()

    try:
        yield db
    finally:
        db.close()


@pytest.mark.asyncio
async def test_auth_persists_flow_state(db_session):
    response = await auth_router.auth(
        app_name="orgmcalc-cli",
        redirect_uri="http://localhost:3000/callback",
        flow_id="flow-123",
        db=db_session,
    )

    state = _extract_state(response.headers["location"])
    state_payload = _decode_state(state)

    assert set(state_payload) == {"sid"}

    oauth_flow = (
        db_session.query(OAuthFlow)
        .filter(OAuthFlow.state_id == state_payload["sid"])
        .one()
    )
    assert oauth_flow.flow_id == "flow-123"
    assert oauth_flow.app_name == "orgmcalc-cli"
    assert oauth_flow.redirect_uri == "http://localhost:3000/callback"
    assert oauth_flow.consumed_at is None


def test_hash_token_handles_long_refresh_tokens_deterministically():
    refresh_token, _ = create_refresh_token(user_id=42)

    assert len(refresh_token) > 72

    token_hash = hash_token(refresh_token)

    assert token_hash == hash_token(refresh_token)
    assert verify_token_hash(refresh_token, token_hash)


@pytest.mark.asyncio
async def test_callback_returns_matching_flow_id_and_consumes_state(
    db_session, monkeypatch
):
    async def fake_exchange_code_for_tokens(code: str) -> dict:
        assert code == "oauth-code"
        return {"access_token": "google-access-token"}

    async def fake_get_google_userinfo(access_token: str) -> dict:
        assert access_token == "google-access-token"
        return {
            "sub": "google-user-1",
            "email": "person@or-gm.com",
            "name": "Person One",
            "picture": "https://example.com/picture.png",
        }

    monkeypatch.setattr(
        auth_router, "exchange_code_for_tokens", fake_exchange_code_for_tokens
    )
    monkeypatch.setattr(auth_router, "get_google_userinfo", fake_get_google_userinfo)

    auth_response = await auth_router.auth(
        app_name="orgmcalc-cli",
        redirect_uri="http://localhost:3000/callback",
        flow_id="cli-flow-1",
        db=db_session,
    )
    state = _extract_state(auth_response.headers["location"])

    callback_response = await auth_router.callback(
        code="oauth-code",
        state=state,
        db=db_session,
        request=_build_request(),
    )

    redirect_query = parse_qs(urlparse(callback_response.headers["location"]).query)
    refresh_token = redirect_query["refresh_token"][0]

    assert redirect_query["flow_id"] == ["cli-flow-1"]

    created_session = db_session.query(SessionModel).one()
    assert verify_token_hash(refresh_token, created_session.refresh_token_hash)

    oauth_flow = db_session.query(OAuthFlow).one()
    assert oauth_flow.consumed_at is not None


@pytest.mark.asyncio
async def test_callback_keeps_parallel_cli_flows_separate(db_session, monkeypatch):
    async def fake_exchange_code_for_tokens(code: str) -> dict:
        return {"access_token": f"google-{code}"}

    async def fake_get_google_userinfo(access_token: str) -> dict:
        user_suffix = access_token.replace("google-", "")
        return {
            "sub": f"sub-{access_token}",
            "email": f"{user_suffix}@or-gm.com",
            "name": access_token,
            "picture": None,
        }

    monkeypatch.setattr(
        auth_router, "exchange_code_for_tokens", fake_exchange_code_for_tokens
    )
    monkeypatch.setattr(auth_router, "get_google_userinfo", fake_get_google_userinfo)

    first_auth = await auth_router.auth(
        app_name="orgmcalc-cli",
        redirect_uri="http://localhost:3000/callback",
        flow_id="cli-flow-a",
        db=db_session,
    )
    second_auth = await auth_router.auth(
        app_name="orgmcalc-cli",
        redirect_uri="http://localhost:3000/callback",
        flow_id="cli-flow-b",
        db=db_session,
    )

    first_callback = await auth_router.callback(
        code="code-a",
        state=_extract_state(first_auth.headers["location"]),
        db=db_session,
        request=_build_request(),
    )
    second_callback = await auth_router.callback(
        code="code-b",
        state=_extract_state(second_auth.headers["location"]),
        db=db_session,
        request=_build_request(),
    )

    first_query = parse_qs(urlparse(first_callback.headers["location"]).query)
    second_query = parse_qs(urlparse(second_callback.headers["location"]).query)

    assert first_query["flow_id"] == ["cli-flow-a"]
    assert second_query["flow_id"] == ["cli-flow-b"]


@pytest.mark.asyncio
async def test_callback_rejects_reused_state(db_session, monkeypatch):
    async def fake_exchange_code_for_tokens(code: str) -> dict:
        return {"access_token": "google-access-token"}

    async def fake_get_google_userinfo(access_token: str) -> dict:
        return {
            "sub": "google-user-2",
            "email": "person@or-gm.com",
            "name": "Person Two",
            "picture": None,
        }

    monkeypatch.setattr(
        auth_router, "exchange_code_for_tokens", fake_exchange_code_for_tokens
    )
    monkeypatch.setattr(auth_router, "get_google_userinfo", fake_get_google_userinfo)

    auth_response = await auth_router.auth(
        app_name="orgmcalc-cli",
        redirect_uri="http://localhost:3000/callback",
        flow_id="cli-flow-reuse",
        db=db_session,
    )
    state = _extract_state(auth_response.headers["location"])

    await auth_router.callback(
        code="oauth-code",
        state=state,
        db=db_session,
        request=_build_request(),
    )

    with pytest.raises(HTTPException) as exc_info:
        await auth_router.callback(
            code="oauth-code",
            state=state,
            db=db_session,
            request=_build_request(),
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "OAuth flow already completed"
