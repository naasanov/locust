from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    GEMINI_API_KEY: str = ""
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "artaas"
    DROPLET_IP: str = ""
    TARGET_URL: str = ""
    TARGET_IP: str = ""
    ENGAGEMENT_ID: str = ""
    SOLANA_PROGRAM_ID: str = ""
    AGENT_KEYPAIR_PATH: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
