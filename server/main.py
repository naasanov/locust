import asyncio
import json
import logging
import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

from src.config import get_settings
from src.container import build_orchestrator
from src.db.mongo import close_db
from src.models.scope import (
    ScopeDocument,
)

load_dotenv()
logger = logging.getLogger(__name__)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = MongoClient(os.getenv("MONGODB_URI"))
db = client[os.getenv("MONGODB_DB", "artaas")]

connected_clients: list[WebSocket] = []


def _get_orch_lock() -> asyncio.Lock:
    lock = getattr(app.state, "orch_run_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        app.state.orch_run_lock = lock
    return lock


@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/api/findings/{eid}")
def get_findings(eid: str):
    findings = list(db.findings.find({"engagement_id": eid}, {"_id": 0}))
    return {"findings": findings}

@app.get("/api/assets/{eid}")
def get_assets(eid: str):
    assets = list(db.assets.find({"engagement_id": eid}, {"_id": 0}))
    return {"assets": assets}

@app.get("/api/chains/{eid}")
def get_chains(eid: str):
    chains = list(db.attack_chains.find({"engagement_id": eid}, {"_id": 0}))
    return {"chains": chains}

@app.get("/api/status")
def get_status():
    return {
        "assets": db.assets.count_documents({}),
        "findings": db.findings.count_documents({}),
        "chains": db.attack_chains.count_documents({})
    }


@app.post("/api/orchestrator/run-once")
async def run_orchestrator_once(scope: ScopeDocument):
    lock = _get_orch_lock()
    logger.warning(
        "run-once requested: engagement_id=%s domains=%s ip_ranges=%s lock_locked=%s",
        scope.engagement_id,
        scope.targets.domains,
        scope.targets.ip_ranges,
        lock.locked(),
    )
    if lock.locked():
        logger.warning(
            "run-once rejected: orchestrator busy for engagement_id=%s",
            scope.engagement_id,
        )
        raise HTTPException(
            status_code=409,
            detail="An orchestrator cycle is already in progress",
        )

    orchestrator = build_orchestrator(broadcast=broadcast)
    timeout_seconds = int(os.getenv("ORCHESTRATOR_RUN_ONCE_TIMEOUT_SECONDS", "900"))
    start = asyncio.get_event_loop().time()
    try:
        logger.warning(
            "run-once starting orchestrator cycle: engagement_id=%s timeout_s=%s",
            scope.engagement_id,
            timeout_seconds,
        )
        async with lock:
            await asyncio.wait_for(orchestrator.run_cycle(scope), timeout=timeout_seconds)
        elapsed = asyncio.get_event_loop().time() - start
        logger.warning(
            "run-once completed orchestrator cycle: engagement_id=%s elapsed_s=%.2f",
            scope.engagement_id,
            elapsed,
        )
    except asyncio.TimeoutError as exc:
        logger.exception(
            "Manual orchestrator run timed out for %s after %ss",
            scope.engagement_id,
            timeout_seconds,
        )
        raise HTTPException(
            status_code=504,
            detail=f"orchestrator run timed out after {timeout_seconds}s",
        ) from exc
    except Exception as exc:
        logger.exception("Manual orchestrator run failed for %s", scope.engagement_id)
        raise HTTPException(status_code=500, detail=f"orchestrator run failed: {exc}") from exc

    return {"status": "ok", "engagement_id": scope.engagement_id}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"ping": "alive"}))
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

async def broadcast(message: dict):
    for client in connected_clients:
        try:
            await client.send_text(json.dumps(message))
        except:
            connected_clients.remove(client)


@app.on_event("startup")
async def startup() -> None:
    settings = get_settings()
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    logging.getLogger("src").setLevel(level)
    logging.getLogger("src.agents").setLevel(level)
    logging.getLogger("src.agents.recon").setLevel(level)
    logging.getLogger("src.agents.exploit").setLevel(level)
    logging.getLogger("src.agents.lateral").setLevel(level)
    logger.info("Configured root/src logger level to %s", settings.LOG_LEVEL.upper())
    logger.info("Orchestrator background loop disabled; use /api/orchestrator/run-once")


@app.on_event("shutdown")
async def shutdown() -> None:
    await close_db()
