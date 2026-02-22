from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    GEMINI_API_KEY: str = ""
    CENSYS_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "artaas"
    DROPLET_IP: str = ""
    TARGET_URL: str = ""
    TARGET_IP: str = ""
    ENGAGEMENT_ID: str = ""
    SOLANA_PROGRAM_ID: str = ""
    AGENT_KEYPAIR_PATH: str = ""
    SOLANA_RPC_URL: str = "https://api.devnet.solana.com"
    LOG_LEVEL: str = "INFO"
    AGENT_RECON_MODE: str = "real"
    AGENT_EXPLOIT_MODE: str = "real"
    AGENT_LATERAL_MODE: str = "real"


@lru_cache
def get_settings() -> Settings:
    return Settings()
