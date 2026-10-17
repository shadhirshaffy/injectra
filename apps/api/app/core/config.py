
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(__file__).resolve().parents[4] / "infrastructure" / ".env"


class Settings(BaseSettings):
    postgres_password: str

    app_environment: str = "production"
    dev_admin_enabled: bool = False
    dev_admin_subject: str | None = None
    dev_admin_token: SecretStr | None = None
    api_key_pepper: SecretStr | None = None
    management_auth_provider: Literal["disabled", "clerk"] = "disabled"
    clerk_issuer: str | None = None
    clerk_secret_key: SecretStr | None = None
    clerk_authorized_parties: list[str] = Field(default_factory=list)
    clerk_audience: str | None = None

    @model_validator(mode="after")
    def authentication_configuration(self):
        if self.dev_admin_enabled and (self.app_environment != "development" or self.management_auth_provider == "clerk"):
            raise ValueError("Development authentication must be isolated to local development")
        if self.management_auth_provider == "clerk":
            issuer = urlsplit(self.clerk_issuer or "")
            if (issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password
                    or issuer.query or issuer.fragment or issuer.path not in ("", "/")):
                raise ValueError("A trusted HTTPS Clerk issuer is required")
            self.clerk_issuer = self.clerk_issuer.rstrip("/")
            if not self.clerk_secret_key or not self.clerk_authorized_parties:
                raise ValueError("Clerk secret key and authorized frontends are required")
            for origin in self.clerk_authorized_parties:
                parsed = urlsplit(origin)
                local = self.app_environment == "development" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                        or parsed.path or parsed.scheme not in ({"http", "https"} if local else {"https"})):
                    raise ValueError("Authorized frontends must be exact secure origins")
        return self

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
