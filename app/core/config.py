import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
IS_VERCEL = os.getenv("VERCEL", "").lower() in {"1", "true", "yes"}
DEFAULT_SQLITE = "sqlite:////tmp/cyberx_osint.db" if IS_VERCEL else f"sqlite:///{(ROOT / 'storage' / 'mr_illogical_osint.db').as_posix()}"
DEFAULT_STORAGE = Path("/tmp/cyber-x-osint") if IS_VERCEL else ROOT / "storage"


class Settings(BaseSettings):
    app_name: str = "Cyber X OSINT"
    app_env: str = "production" if IS_VERCEL else "development"
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = DEFAULT_SQLITE
    api_token: str = ""
    credential_encryption_key: str = ""
    exposure_hmac_key: str = ""
    authorized_databases_json: str = "{}"
    max_upload_mb: int = 15
    request_timeout_seconds: float = 8.0
    user_agent: str = "Cyber-X-OSINT/1.5 (+public-html-research; contact: operator-configured)"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
ROOT_DIR = ROOT
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(DEFAULT_STORAGE))).resolve()
for _folder in (STORAGE_DIR, STORAGE_DIR / "uploads", STORAGE_DIR / "evidence", STORAGE_DIR / "reports"):
    _folder.mkdir(parents=True, exist_ok=True)
