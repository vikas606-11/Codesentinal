from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/rules (local) or /app/rules (Docker)
DEFAULT_RULES_DIR = str(Path(__file__).resolve().parents[1] / "rules")
# backend/data (local) or /app/data (Docker, mounted as a volume)
DEFAULT_DB_PATH = str(Path(__file__).resolve().parents[1] / "data" / "codesentinel.db")


class Settings(BaseSettings):
    app_name: str = "CodeSentinel"
    app_version: str = "0.5.0"
    environment: str = "development"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Semgrep: binary path and rule sources (comma-separated: folders, files, or registry packs like p/python)
    semgrep_bin: str = "semgrep"
    semgrep_config: str = DEFAULT_RULES_DIR

    # Other scanners (binaries are installed in the Docker image)
    gitleaks_bin: str = "gitleaks"
    trivy_bin: str = "trivy"
    trivy_timeout_seconds: int = 120
    trivy_auto_download_db: bool = False  # True = download the database during a scan if missing (slow)
    trivy_refresh_db: bool = False  # False = reuse the cached database when one exists

    # AI explanations. provider: mock (default, no key needed) | anthropic | openai (any OpenAI-compatible API)
    ai_provider: str = "mock"
    ai_api_key: str = ""
    ai_model: str = ""  # empty = a sensible default for the provider
    ai_base_url: str = ""  # empty = the provider's official address
    ai_timeout_seconds: int = 30

    # Storage and quality gate
    database_path: str = DEFAULT_DB_PATH
    quality_gate_threshold: int = 70  # score >= threshold -> PASS

    # Upload and scan limits
    max_upload_mb: int = 20
    max_unzipped_mb: int = 100
    max_zip_files: int = 5000
    scan_timeout_seconds: int = 120
    workspace_dir: str = ""  # empty = system temp directory

    # Reads backend/.env or ./.env if present; real environment variables win.
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def semgrep_config_list(self) -> list[str]:
        return [c.strip() for c in self.semgrep_config.split(",") if c.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
