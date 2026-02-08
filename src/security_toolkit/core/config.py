"""Application configuration management."""

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_prefix="SECKIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database settings
    db_path: Path = Field(
        default=Path.home() / ".seckit" / "seckit.db",
        description="Path to SQLite database file",
    )

    # AWS settings
    aws_profile: str | None = Field(
        default=None,
        description="AWS profile name to use",
    )
    aws_region: str = Field(
        default="us-east-1",
        description="Default AWS region",
    )

    # Script settings
    scripts_dir: Path = Field(
        default=Path.home() / ".seckit" / "scripts",
        description="Directory for custom scripts",
    )
    max_script_runtime: int = Field(
        default=3600,
        description="Maximum script execution time in seconds",
    )

    # Output settings
    output_dir: Path = Field(
        default=Path.cwd() / "output",
        description="Default output directory for reports",
    )
    default_format: str = Field(
        default="json",
        description="Default output format (json, csv, html, md)",
    )

    # Logging settings
    log_level: str = Field(
        default="INFO",
        description="Logging level",
    )
    log_file: Path | None = Field(
        default=None,
        description="Log file path (None for console only)",
    )

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_config_value(self, key: str) -> Any:
        """Get a configuration value by key."""
        return getattr(self, key, None)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    settings.ensure_directories()
    return settings
