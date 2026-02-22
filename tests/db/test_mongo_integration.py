"""
Quick integration test for src/db/mongo.py against a live MongoDB instance.

Run:
    pytest tests/db/test_mongo_integration.py -v -s -rs
"""

import uuid
from datetime import datetime, timezone

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from src.config import get_settings
from src.db import mongo
from src.models.asset import AssetDocument
from src.models.attack_chain import AttackChain, PivotStep
from src.models.finding import Evidence, FindingDocument


async def _mongo_reachable(uri: str) -> bool:
    client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=1500)
    try:
        await client.admin.command("ping")
        return True
    except Exception:
        return False
    finally:
        client.close()


@pytest.mark.asyncio
async def test_mongo_roundtrip_assets_findings_and_chains():
    settings = get_settings()
    assert await _mongo_reachable(settings.MONGODB_URI)

    engagement_id = f"integ-mongo-{uuid.uuid4()}"
    db = mongo.get_db()

    asset = AssetDocument(
        engagement_id=engagement_id,
        asset_type="web_app",
        url="http://localhost:3000",
        ip="127.0.0.1",
        open_ports=[3000, 3306],
        attack_surface_score=0.91,
        score_reasoning="Integration test fixture",
    )
    finding = FindingDocument(
        engagement_id=engagement_id,
        asset_id=asset.asset_id,
        finding_id=str(uuid.uuid4()),
        vulnerability_class="credential_exposure",
        title="Exposed .env test fixture",
        severity="critical",
        exploitable=True,
        affected_url="http://localhost:8000/.env",
        evidence=Evidence(
            request="GET /.env HTTP/1.1\nHost: localhost:8000",
            response_snippet="DB_USER=juice_admin\nDB_PASSWORD=s3cr3tpass!",
            status_code=200,
        ),
        blast_radius="multi_asset",
    )
    chain = AttackChain(
        engagement_id=engagement_id,
        chain_id=str(uuid.uuid4()),
        entry_point_finding_id=finding.finding_id,
        entry_point="http://localhost:8000/.env",
        pivot_path=[
            PivotStep(
                step=1,
                asset="localhost",
                action="Read .env",
                detail="Extracted DB credentials",
                mitre="T1552.001",
            )
        ],
        blast_radius_score=0.8,
        blast_radius_summary="Database compromise possible.",
        gemini_reasoning="Integration test fixture chain.",
        discovered_at=datetime.now(timezone.utc),
    )

    try:
        print(f"\nMongo URI: {settings.MONGODB_URI}")
        print(f"Mongo DB: {settings.MONGODB_DB}")
        print(f"Engagement: {engagement_id}")

        await mongo.save_assets(db, [asset])
        await mongo.save_findings(db, [finding])
        await mongo.save_attack_chains(db, [chain])

        assets = await mongo.get_assets(db, engagement_id=engagement_id, min_score=0.0)
        findings = await mongo.get_findings(
            db, engagement_id=engagement_id, exploitable=True, blast_radius="multi_asset"
        )
        chains = await mongo.get_attack_chains(db, engagement_id=engagement_id)

        print(f"assets fetched: {len(assets)}")
        print(f"findings fetched: {len(findings)}")
        print(f"chains fetched: {len(chains)}")

        assert len(assets) == 1
        assert len(findings) == 1
        assert len(chains) == 1
        assert assets[0].engagement_id == engagement_id
        assert findings[0].finding_id == finding.finding_id
        assert chains[0].entry_point_finding_id == finding.finding_id
    finally:
        await db["assets"].delete_many({"engagement_id": engagement_id})
        await db["findings"].delete_many({"engagement_id": engagement_id})
        await db["attack_chains"].delete_many({"engagement_id": engagement_id})
        await mongo.close_db()
