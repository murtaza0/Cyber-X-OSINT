import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "Cyber X OSINT"
    app_env: str = "production" if os.getenv("VERCEL", "").lower() in {"1", "true", "yes"} else "development"
    api_token: str = ""
    request_timeout_seconds: float = 8.0
    user_agent: str = "Cyber-X-OSINT/2.0 (+public-web-research; operator-configured)"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
ROOT_DIR = ROOT
