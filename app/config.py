from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    ORGM_SECRET_KEY: str

    ALLOWED_DOMAIN: str = "or-gm.com"
    BASE_URL: str = "https://auth.or-gm.com"
    LOCAL_BASE_URL: str = "http://localhost:8500"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    @property
    def auth_url(self) -> str:
        return f"{self.BASE_URL}/auth"

    @property
    def callback_url(self) -> str:
        return f"{self.BASE_URL}/callback"


settings = Settings()
