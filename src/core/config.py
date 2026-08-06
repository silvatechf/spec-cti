"""
Central configuration for CyberLab-Enterprise.

All settings are loaded from environment variables (with safe local-dev
defaults) using Pydantic's BaseSettings so misconfiguration fails fast and
loudly rather than silently at runtime.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Strongly-typed application settings.

    Values are sourced from environment variables first, falling back to
    the defaults below, which are intentionally safe for local lab use only.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Environment ----------------------------------------------------
    environment: Literal["lab", "ci", "test"] = "lab"
    log_level: str = "INFO"

    # --- Database ---------------------------------------------------------
    database_url: str = Field(
        default="postgresql+psycopg2://cyberlab:devpassword_change_me@localhost:5432/cyberlab",
        description="SQLAlchemy connection string for the vulnerability/event DB.",
    )

    # --- Docker / lab network -------------------------------------------
    lab_network_name: str = Field(
        default="cyberlab-enterprise_lab_network",
        description="Name of the isolated Docker bridge network the target containers live on.",
    )
    docker_socket: str = "/var/run/docker.sock"

    # --- Paths ------------------------------------------------------------
    data_dir: Path = PROJECT_ROOT / "data"
    reports_dir: Path = PROJECT_ROOT / "reports"
    wordlists_dir: Path = PROJECT_ROOT / "data" / "wordlists"
    cve_lookup_path: Path = PROJECT_ROOT / "data" / "cve_lookup.json"

    # --- Exploit simulator guardrails --------------------------------------
    # These are hard safety boundaries, not user-configurable via env vars,
    # to prevent the ransomware simulator from ever being pointed elsewhere.
    ransomware_sandbox_path: str = "/tmp/lab-target"
    ransomware_test_key: str = "CyberLab-Enterprise-DevOnly-Fixed-Key-2024"  # noqa: S105 - intentional, lab-only

    # --- CTF engine ---------------------------------------------------------
    ctf_flag_prefix: str = "CTF"
    ctf_hint_penalty_pct: float = 0.15  # % of point value deducted per hint

    # --- API ---------------------------------------------------------------
    api_host: str = "0.0.0.0"  # noqa: S104 - intentionally binds inside container
    api_port: int = 8000

    # --- Monitoring ---------------------------------------------------------
    elasticsearch_url: str = "http://localhost:9200"
    alert_failed_login_threshold: int = 5
    alert_window_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    """Return a cached, process-wide Settings instance."""
    return Settings()
