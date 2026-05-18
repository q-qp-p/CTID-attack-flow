from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProviderConfig(BaseModel):
    id: str
    type: str
    enabled: bool = True
    base_url: str | None = None
    api_key_env: str | None = None
    default_model: str | None = None
    models: list[str] = Field(default_factory=list)


class ProvidersConfig(BaseModel):
    providers: list[ProviderConfig] = Field(default_factory=list)


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = Field(default="attack-flow-api", validation_alias="APP_NAME")
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    api_host: str = Field(default="127.0.0.1", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")
    api_prefix: str = Field(default="/api/v1", validation_alias="API_PREFIX")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    cors_enabled: bool = Field(default=False, validation_alias="CORS_ENABLED")
    cors_allow_origins: str = Field(default="", validation_alias="CORS_ALLOW_ORIGINS")
    cors_allow_credentials: bool = Field(
        default=False, validation_alias="CORS_ALLOW_CREDENTIALS"
    )
    cors_allow_methods: str = Field(default="*", validation_alias="CORS_ALLOW_METHODS")
    cors_allow_headers: str = Field(default="*", validation_alias="CORS_ALLOW_HEADERS")
    data_dir: Path = Field(default=Path("data"), validation_alias="DATA_DIR")
    sqlite_path: Path = Field(
        default=Path("data/attack-flow.db"), validation_alias="SQLITE_PATH"
    )
    upload_dir: Path = Field(default=Path("data/uploads"), validation_alias="UPLOAD_DIR")
    artifact_dir: Path = Field(
        default=Path("data/artifacts"), validation_alias="ARTIFACT_DIR"
    )
    file_storage_strict_mode: bool = Field(
        default=True, validation_alias="FILE_STORAGE_STRICT_MODE"
    )
    file_storage_max_bytes: int | None = Field(
        default=None, validation_alias="FILE_STORAGE_MAX_BYTES"
    )
    raw_text_max_chars: int = Field(default=200000, validation_alias="RAW_TEXT_MAX_CHARS")
    providers_config_path: Path = Field(
        default=Path("config/providers.yml"), validation_alias="PROVIDERS_CONFIG_PATH"
    )


def load_settings() -> AppSettings:
    return AppSettings()


def load_providers_config(config_path: Path) -> ProvidersConfig:
    if not config_path.exists():
        raise FileNotFoundError(f"Provider config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as config_file:
        raw_data = yaml.safe_load(config_file)

    if raw_data is None:
        raw_data = {}
    if not isinstance(raw_data, dict):
        raise ValueError("Provider config YAML root must be a mapping")

    try:
        return ProvidersConfig.model_validate(raw_data)
    except ValidationError as error:
        raise ValueError("Provider config validation failed") from error


def resolve_runtime_paths(settings: AppSettings) -> dict[str, Path]:
    return {
        "data_dir": settings.data_dir,
        "sqlite_path": settings.sqlite_path,
        "upload_dir": settings.upload_dir,
        "artifact_dir": settings.artifact_dir,
    }


def ensure_runtime_directories(runtime_paths: dict[str, Path]) -> None:
    runtime_paths["data_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["upload_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["artifact_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["sqlite_path"].parent.mkdir(parents=True, exist_ok=True)
