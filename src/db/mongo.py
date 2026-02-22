from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from src.config import get_settings
from src.models.asset import AssetDocument
from src.models.attack_chain import AttackChain
from src.models.finding import FindingDocument

_client: AsyncIOMotorClient | None = None


def get_db() -> AsyncIOMotorDatabase:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(get_settings().MONGODB_URI)
    client: AsyncIOMotorClient = _client
    return client[get_settings().MONGODB_DB]


async def close_db() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


async def save_assets(db: AsyncIOMotorDatabase, assets: list[AssetDocument]) -> None:
    if not assets:
        return
    docs = [a.model_dump(mode="json") for a in assets]
    await db["assets"].insert_many(docs)


async def get_assets(
    db: AsyncIOMotorDatabase,
    engagement_id: str,
    min_score: float = 0.0,
    limit: int | None = None,
) -> list[AssetDocument]:
    cursor = db["assets"].find(
        {
            "engagement_id": engagement_id,
            "attack_surface_score": {"$gte": min_score},
        }
    ).sort("attack_surface_score", -1)
    if limit is not None:
        cursor = cursor.limit(limit)
    return [AssetDocument.model_validate(doc) async for doc in cursor]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


async def save_findings(
    db: AsyncIOMotorDatabase, findings: list[FindingDocument]
) -> None:
    if not findings:
        return
    docs = [f.model_dump(mode="json") for f in findings]
    await db["findings"].insert_many(docs)


async def get_findings(
    db: AsyncIOMotorDatabase,
    engagement_id: str,
    exploitable: bool = True,
    blast_radius: str | None = None,
) -> list[FindingDocument]:
    query: dict = {"engagement_id": engagement_id, "exploitable": exploitable}
    if blast_radius is not None:
        query["blast_radius"] = blast_radius
    cursor = db["findings"].find(query).sort("severity", 1)
    return [FindingDocument.model_validate(doc) async for doc in cursor]


# ---------------------------------------------------------------------------
# Attack chains
# ---------------------------------------------------------------------------


async def save_attack_chains(
    db: AsyncIOMotorDatabase, chains: list[AttackChain]
) -> None:
    if not chains:
        return
    docs = [c.model_dump(mode="json") for c in chains]
    await db["attack_chains"].insert_many(docs)


async def get_attack_chains(
    db: AsyncIOMotorDatabase,
    engagement_id: str,
) -> list[AttackChain]:
    cursor = db["attack_chains"].find({"engagement_id": engagement_id})
    return [AttackChain.model_validate(doc) async for doc in cursor]
