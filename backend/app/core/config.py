from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: str = "development"
    APP_NAME: str = "Secure JEE/NEET Self-Study MVP"

    # Database
    DATABASE_URL: str = "postgresql+psycopg2://app_user:changeme@localhost:5432/appdb"

    # JWT / Auth
    JWT_SECRET_KEY: str = "CHANGE_ME_IN_PROD_32BYTES_MIN"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CSRF
    CSRF_SECRET_KEY: str = "CHANGE_ME_CSRF_SECRET"

    # CORS
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    # Rate limiting
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "5/minute"

    # Redis (production rate limit/session backing)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Password hashing
    BCRYPT_ROUNDS: int = 12

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
