"""All settings come from environment variables (or the local .env file)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- storage -----------------------------------------------------------
    data_dir: Path = Path("./data")
    database_url: str = ""  # empty -> sqlite file in data_dir
    redis_url: str = "redis://localhost:6379/0"

    # --- API ---------------------------------------------------------------
    vulnscan_api_key: str = ""  # if set, API requires header X-API-Key
    max_upload_mb: int = 500

    # --- scope / authorization -------------------------------------------
    # Hosts (or CIDRs, or *.domain) that may be actively scanned without
    # ownership verification. Everything else must be verified first.
    allowed_targets: str = "localhost,127.0.0.1,juice-shop,dvwa,demo-chat,host.docker.internal"
    require_ownership_verification: bool = True
    allow_private_networks: bool = False

    # --- execution ---------------------------------------------------------
    max_parallel_tools: int = 3
    tool_timeout: int = 1800  # seconds, per tool

    # --- LLM (planner / triage / report writing / AI judge) ----------------
    llm_provider: str = "none"  # none | ollama | anthropic | openai_compat
    llm_model: str = ""
    ollama_url: str = "http://ollama:11434"
    anthropic_api_key: str = ""
    openai_compat_base_url: str = ""  # e.g. https://generativelanguage.googleapis.com/v1beta/openai
    openai_compat_api_key: str = ""
    llm_triage: bool = True
    llm_max_findings_to_triage: int = 40

    # --- AI security -------------------------------------------------------
    hf_token: str = ""
    prompt_guard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    prompt_guard_threshold: float = 0.5

    # --- external services -------------------------------------------------
    github_token: str = ""
    zap_url: str = "http://zap:8080"
    zap_api_key: str = ""
    gvm_socket: str = "/run/gvmd/gvmd.sock"
    gvm_username: str = "admin"
    gvm_password: str = "admin"

    # --- enrichment --------------------------------------------------------
    enrich_online: bool = True  # EPSS + CISA KEV lookups

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{(self.data_dir / 'vulnscan.db').resolve()}"

    @property
    def scans_dir(self) -> Path:
        p = self.data_dir / "scans"
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()
