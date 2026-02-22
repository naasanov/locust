"""MongoDB connection management."""

from functools import lru_cache
from typing import Optional

from pymongo import MongoClient
from pymongo.database import Database

from config.settings import get_settings


@lru_cache
def get_client() -> MongoClient:
    """Get cached MongoDB client."""
    settings = get_settings()
    return MongoClient(settings.mongodb_uri)


def get_database(client: Optional[MongoClient] = None) -> Database:
    """Get the application database."""
    settings = get_settings()
    client = client or get_client()
    return client[settings.mongodb_database]


def init_indexes(db: Database) -> None:
    """Initialize MongoDB indexes for collections."""
    # Assets collection indexes
    db.assets.create_index("engagement_id")
    db.assets.create_index("ip")
    db.assets.create_index("url")
    db.assets.create_index([("attack_surface_score", -1)])
    db.assets.create_index([("_metadata.discovered_at", -1)])

    # Engagements collection indexes
    db.engagements.create_index("engagement_id", unique=True)
    db.engagements.create_index("customer")
    db.engagements.create_index([("constraints.expires_at", 1)])
