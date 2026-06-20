from datetime import timedelta
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(
            BASE_DIR / ".env",
            BASE_DIR / ".env.local",
            BASE_DIR / "app" / ".env.local",
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENV: str = "local"
    BASE_DIR: Path = BASE_DIR

    DATABASE_URL: str
    DATABASE_ECHO: bool = False
    SECRET_KEY: str
    DEBUG: bool = False
    ALLOWED_HOSTS: list[str] = ["localhost", "127.0.0.1"]
    ALLOWED_METHODS: list[str] = ["get", "post", "patch", "delete"]

    PASSWORD_RESET_MAX_REQUESTS_PER_DAY: int = 5
    PASSWORD_RESET_TOKEN_EXPIRY_MINUTES: int = 15
    COOLDOWN_STEPS: list[timedelta] = [
        timedelta(minutes=1),
        timedelta(minutes=5),
        timedelta(minutes=15),
        timedelta(hours=1),
        timedelta(hours=6),
    ]

    EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES: int = 30

    FRONTEND_URL: str = "http://localhost:3000"
    APP_NAME: str = "Online Duuka"

    GOOGLE_CLIENT_ID: str
    GOOGLE_SECRET_KEY: str = Field(
        validation_alias=AliasChoices("GOOGLE_SECRET_KEY", "GOOGLE_CLIENT_SECRET"),
    )
    GOOGLE_REDIRECT_URI: str
    GOOGLE_OAUTH_STATE_PREFIX: str = "google:oauth:state"
    GOOGLE_OAUTH_STATE_TTL_SECONDS: int = 2 * 60

    SMTP_HOST: str
    SMTP_PORT: int = 587
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    SMTP_FROM_EMAIL: str
    SMTP_FROM_NAME: str = "Online Duuka"
    SMTP_STARTTLS: bool = True
    SMTP_USE_TLS: bool = False
    MAX_EMAIL_RETRIES: int = 2
    DEFAULT_RETRY_DELAY_SECONDS: int = 30

    CELERY_BROKER_URL: str
    CELERY_EXPIRY_SECONDS: int = 300
    CELERY_RESULT_BACKEND: str

    JWT_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
        ),
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        validation_alias=AliasChoices(
            "REFRESH_TOKEN_EXPIRE_DAYS",
            "JWT_REFRESH_TOKEN_EXPIRE_DAYS",
        ),
    )
    GOOGLE_TOKEN_EXPIRE_MINUTES: int = 2
    REFRESH_TOKEN_EXPIRE_REMEMBER_ME_DAYS: int = 30
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "Online Duuka"
    JWT_AUDIENCE: str = "your-app-client"

    MAX_ACTIVE_SESSIONS_PER_USER: int = 5
    TWO_FACTOR_CHALLENGE_EXPIRE_MINUTES: int = 5
    TWO_FACTOR_MAX_ATTEMPTS: int = 5
    TWO_FACTOR_TOTP_DIGITS: int = 6
    TWO_FACTOR_TOTP_PERIOD_SECONDS: int = 30
    TWO_FACTOR_TOTP_VALID_WINDOW: int = 1
    TWO_FACTOR_RECOVERY_CODE_COUNT: int = 10
    TWO_FACTOR_RECOVERY_CODE_LENGTH: int = 10
    TWO_FACTOR_SECRET_ENCRYPTION_KEY: str | None = None

    REDIS_URL: str

    AUTH_RATE_LIMIT_LOCAL: str = "unlimited"
    AUTH_RATE_LIMIT_DEVELOPMENT: str = "100/minute"
    AUTH_RATE_LIMIT_PRODUCTION: str = "10/minute"

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug(cls, value):
        production_values = {"prod", "production", "release"}
        if isinstance(value, str) and value.lower() in production_values:
            return False
        return value


settings = Settings()  # type: ignore[call-arg]
