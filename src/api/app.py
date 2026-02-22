"""API surface for orchestrator and dashboard consumption."""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from src.container import build_orchestrator
from src.db import mongo
from src.db.mongo import get_db
from src.models.scope import ScopeDocument

app = FastAPI(title="artaas API", version="0.1.0")


class ReconRunRequest(BaseModel):
    scope: ScopeDocument
    on_chain_hash: str | None = None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/assets")
async def list_assets(
    engagement_id: str = Query(..., min_length=1),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    db = get_db()
    assets = await mongo.get_assets(db, engagement_id=engagement_id, min_score=min_score)
    assets = assets[:limit]
    return {
        "engagement_id": engagement_id,
        "count": len(assets),
        "assets": [asset.model_dump(mode="json") for asset in assets],
    }


@app.post("/api/recon/run")
async def run_recon_cycle(payload: ReconRunRequest) -> dict:
    orchestrator = build_orchestrator()

    if payload.on_chain_hash is not None:
        scope_doc = payload.scope.model_dump(mode="json")
        if not orchestrator.recon.verify_scope_integrity(scope_doc, payload.on_chain_hash):
            raise HTTPException(status_code=400, detail="Scope integrity check failed.")

    try:
        await orchestrator.run_cycle(payload.scope)
    except ValueError as exc:
        # Most common runtime issue is missing GEMINI_API_KEY.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = get_db()
    assets = await mongo.get_assets(db, payload.scope.engagement_id)
    return {
        "engagement_id": payload.scope.engagement_id,
        "assets_discovered": len(assets),
    }
