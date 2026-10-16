
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(__file__).resolve().parents[4] / "infrastructure" / ".env"


class Settings(BaseSettings):
    postgres_password: str

    app_environment: str = "production"
    dev_admin_enabled: bool = False
    dev_admin_subject: str | None = None
    dev_admin_token: SecretStr | None = None
    api_key_pepper: SecretStr | None = None

    database_host: str = "127.0.0.1"
    database_port: int = 5433
    database_user: str = "injectra"
    database_name: str = "injectra_db"

    redis_url: str = "redis://127.0.0.1:6379/0"

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


settings = Settings()
