from pathlib import Path

from tests.key_material import (
    TEST_ACCESS_TOKEN_PRIVATE_KEY,
    TEST_ACCESS_TOKEN_PUBLIC_KEY,
)


TEST_DB_PATH = Path(__file__).resolve().parent / "test_oauth_flow.db"


def pytest_configure() -> None:
    import os

    os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")
    os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
    os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-client-secret")
    os.environ.setdefault("ACCESS_TOKEN_ACTIVE_KID", "test-rs256-key")
    os.environ.setdefault("ACCESS_TOKEN_PRIVATE_KEY_PEM", TEST_ACCESS_TOKEN_PRIVATE_KEY)
    os.environ.setdefault("ACCESS_TOKEN_PUBLIC_KEY_PEM", TEST_ACCESS_TOKEN_PUBLIC_KEY)
