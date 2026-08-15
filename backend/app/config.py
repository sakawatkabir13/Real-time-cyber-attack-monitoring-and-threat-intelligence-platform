from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "postgresql+asyncpg://vanguard:change_me_strong_password@postgres:5432/vanguardmap"
    DATABASE_SSL: bool = False
    REDIS_URL: str = "redis://redis:6379/0"
    COLLECTOR_TOKEN: str = "change_me_long_random_token_for_agent_auth"
    DASHBOARD_PASSWORD: str = "change_me_dashboard_password"
    ABUSEIPDB_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    MODEL_PATH: str = "/models/behavioral_models.joblib"
    SECRET_KEY: str = "change_me_long_random_secret_for_jwt"
    CORS_ORIGINS: list[str] = []
    MAXMIND_DB_PATH: str = ""
    COOKIE_SECURE: bool = False
    SESSION_TTL_SECONDS: int = Field(default=43_200, ge=300, le=604_800)
    MAX_LOG_SIZE_BYTES: int = Field(default=50 * 1024 * 1024, ge=1024, le=1024**3)
    MAX_INGEST_BATCH_SIZE: int = Field(default=250, ge=1, le=5000)
    MAX_WEBSOCKET_CONNECTIONS: int = Field(default=200, ge=1, le=10_000)
    EVENT_RETENTION_DAYS: int = Field(default=30, ge=1, le=3650)
    ALERT_DEDUPE_SECONDS: int = Field(default=900, ge=60, le=86_400)
    COLLECTOR_OFFLINE_SECONDS: int = Field(default=45, ge=15, le=3600)
    ML_SERVER_WINDOW_SECONDS: int = Field(default=60, ge=10, le=3600)
    ML_SOURCE_WINDOW_SECONDS: int = Field(default=300, ge=10, le=86_400)
    ML_WINDOW_GRACE_SECONDS: int = Field(default=20, ge=0, le=3600)
    ML_MIN_SERVER_REQUESTS: int = Field(default=20, ge=1)
    ML_MIN_SOURCE_REQUESTS: int = Field(default=5, ge=1)
    ML_MIN_TRAINING_WINDOWS: int = Field(default=200, ge=5, le=100_000)
    ML_MAX_TRAINING_WINDOWS: int = Field(default=20_000, ge=5, le=1_000_000)
    ML_TRAINING_DAYS: int = Field(default=30, ge=1, le=3650)
    ML_CONTAMINATION: float = Field(default=0.02, gt=0.0, lt=0.5)
    ML_ALERT_SCORE: float = Field(default=90.0, ge=50.0, le=100.0)
    ML_MAX_VALIDATION_ALERT_FRACTION: float = Field(
        default=0.10, ge=0.0, le=0.5
    )
    TARGET_LATITUDE: float | None = None
    TARGET_LONGITUDE: float | None = None

    def validate_production_secrets(self) -> None:
        if self.ENVIRONMENT.lower() != "production":
            return
        insecure = {
            "COLLECTOR_TOKEN": self.COLLECTOR_TOKEN,
            "DASHBOARD_PASSWORD": self.DASHBOARD_PASSWORD,
            "SECRET_KEY": self.SECRET_KEY,
        }
        invalid = [name for name, value in insecure.items() if not value or value.startswith("change_me")]
        if not self.COOKIE_SECURE:
            invalid.append("COOKIE_SECURE")
        if invalid:
            raise RuntimeError(
                "Refusing to start production with insecure settings: " + ", ".join(invalid)
            )

settings = Settings()
