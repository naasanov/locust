"""Application settings loaded from environment."""

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    """Application configuration."""

    # MongoDB
    mongodb_uri: str
    mongodb_database: str

    # API Keys
    gemini_api_key: str
    shodan_api_key: str | None

    # Solana
    solana_rpc_url: str

    # Agent Config
    recon_cycle_interval_hours: int
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables."""
        return cls(
            mongodb_uri=os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
            mongodb_database=os.getenv("MONGODB_DATABASE", "uncp"),
            gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
            shodan_api_key=os.getenv("SHODAN_API_KEY"),
            solana_rpc_url=os.getenv(
                "SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"
            ),
            recon_cycle_interval_hours=int(
                os.getenv("RECON_CYCLE_INTERVAL_HOURS", "24")
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )

    def validate(self) -> list[str]:
        """Validate required settings are present."""
        errors = []

        if not self.gemini_api_key:
            errors.append("GEMINI_API_KEY is required")

        if not self.mongodb_uri:
            errors.append("MONGODB_URI is required")

        return errors


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings.from_env()
