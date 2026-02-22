"""API surface for orchestrator and dashboard consumption."""

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.container import build_orchestrator
from src.db import mongo
from src.db.mongo import close_db, get_db
from src.models.scope import ScopeDocument

logger = logging.getLogger(__name__)

_RECON_RUNS: dict[str, dict[str, Any]] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
    if configured:
        origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
        if origins:
            return origins
    return ["http://localhost:3000", "http://127.0.0.1:3000"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Warm up DB client on startup so first request is predictable.
    get_db()
    yield
    await close_db()


app = FastAPI(title="artaas API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReconRunRequest(BaseModel):
    scope: ScopeDocument
    on_chain_hash: str | None = None


def _start_recon_task(run_id: str, payload: ReconRunRequest, orchestrator: Any) -> None:
    asyncio.create_task(_run_recon_job(run_id, payload, orchestrator))


async def _run_recon_job(run_id: str, payload: ReconRunRequest, orchestrator: Any) -> None:
    _RECON_RUNS[run_id]["status"] = "running"
    _RECON_RUNS[run_id]["started_at"] = _utc_now()

    try:
        await orchestrator.run_cycle(payload.scope)

        db = get_db()
        assets_discovered = await db["assets"].count_documents(
            {"engagement_id": payload.scope.engagement_id}
        )
        _RECON_RUNS[run_id]["status"] = "completed"
        _RECON_RUNS[run_id]["assets_discovered"] = int(assets_discovered)
        _RECON_RUNS[run_id]["finished_at"] = _utc_now()
    except ValueError as exc:
        _RECON_RUNS[run_id]["status"] = "failed"
        _RECON_RUNS[run_id]["detail"] = str(exc)
        _RECON_RUNS[run_id]["finished_at"] = _utc_now()
    except Exception:
        logger.exception("Unexpected error during recon cycle run %s", run_id)
        _RECON_RUNS[run_id]["status"] = "failed"
        _RECON_RUNS[run_id]["detail"] = "Internal error while running recon cycle."
        _RECON_RUNS[run_id]["finished_at"] = _utc_now()


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
    assets = await mongo.get_assets(
        db,
        engagement_id=engagement_id,
        min_score=min_score,
        limit=limit,
    )
    return {
        "engagement_id": engagement_id,
        "count": len(assets),
        "assets": [asset.model_dump(mode="json") for asset in assets],
    }


@app.post("/api/recon/run", status_code=202)
async def run_recon_cycle(payload: ReconRunRequest) -> dict:
    try:
        orchestrator = build_orchestrator()
    except Exception as exc:
        logger.exception("Could not initialize orchestrator")
        raise HTTPException(status_code=500, detail="Failed to initialize orchestrator.") from exc

    if payload.on_chain_hash is not None:
        scope_doc = payload.scope.model_dump(mode="json")
        if not orchestrator.recon.verify_scope_integrity(scope_doc, payload.on_chain_hash):
            raise HTTPException(status_code=400, detail="Scope integrity check failed.")

    run_id = str(uuid.uuid4())
    _RECON_RUNS[run_id] = {
        "run_id": run_id,
        "engagement_id": payload.scope.engagement_id,
        "status": "queued",
        "submitted_at": _utc_now(),
    }

    try:
        _start_recon_task(run_id, payload, orchestrator)
    except Exception as exc:
        logger.exception("Failed to schedule recon cycle")
        _RECON_RUNS[run_id]["status"] = "failed"
        _RECON_RUNS[run_id]["detail"] = "Failed to schedule recon cycle."
        _RECON_RUNS[run_id]["finished_at"] = _utc_now()
        raise HTTPException(status_code=500, detail="Failed to schedule recon cycle.") from exc

    return _RECON_RUNS[run_id]


@app.get("/api/recon/run/{run_id}")
async def get_recon_run(run_id: str) -> dict:
    run = _RECON_RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Recon run not found.")
    return run

