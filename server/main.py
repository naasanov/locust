import asyncio
import json
import os
import traceback

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

from src.config import get_settings
from src.container import build_orchestrator
from src.db.mongo import close_db
from src.models.scope import ScopeDocument
from src.services import get_ws_event_service

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

client = MongoClient(os.getenv("MONGODB_URI"))
db = client[os.getenv("MONGODB_DB", "artaas")]

ws_events = get_ws_event_service()


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
        "chains": db.attack_chains.count_documents({}),
    }


@app.post("/api/orchestrator/run-once")
async def run_orchestrator_once(scope: ScopeDocument):
    lock = _get_orch_lock()
    print(
        "[server] run-once requested: "
        f"engagement_id={scope.engagement_id} "
        f"domains={scope.targets.domains} "
        f"ip_ranges={scope.targets.ip_ranges} "
        f"lock_locked={lock.locked()}"
    )
    if lock.locked():
        print(
            "[server] run-once rejected: orchestrator busy "
            f"for engagement_id={scope.engagement_id}"
        )
        raise HTTPException(
            status_code=409,
            detail="An orchestrator cycle is already in progress",
        )

    orchestrator = build_orchestrator(broadcast=ws_events.emit)
    timeout_seconds = int(os.getenv("ORCHESTRATOR_RUN_ONCE_TIMEOUT_SECONDS", "900"))
    start = asyncio.get_event_loop().time()
    try:
        print(
            "[server] run-once starting orchestrator cycle: "
            f"engagement_id={scope.engagement_id} timeout_s={timeout_seconds}"
        )
        async with lock:
            await asyncio.wait_for(
                orchestrator.run_cycle(scope), timeout=timeout_seconds
            )
        elapsed = asyncio.get_event_loop().time() - start
        print(
            "[server] run-once completed orchestrator cycle: "
            f"engagement_id={scope.engagement_id} elapsed_s={elapsed:.2f}"
        )
    except asyncio.TimeoutError as exc:
        print(
            "[server] ERROR: manual orchestrator run timed out "
            f"for {scope.engagement_id} after {timeout_seconds}s"
        )
        print(traceback.format_exc())
        raise HTTPException(
            status_code=504,
            detail=f"orchestrator run timed out after {timeout_seconds}s",
        ) from exc
    except Exception as exc:
        print(
            f"[server] ERROR: manual orchestrator run failed for {scope.engagement_id}"
        )
        print(traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"orchestrator run failed: {exc}"
        ) from exc

    return {"status": "ok", "engagement_id": scope.engagement_id}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await ws_events.register(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"ping": "alive"}))
    except WebSocketDisconnect:
        await ws_events.unregister(websocket)


@app.on_event("startup")
async def startup() -> None:
    settings = get_settings()
    print(f"[server] startup complete (LOG_LEVEL={settings.LOG_LEVEL.upper()})")
    print(
        "[server] Orchestrator background loop disabled; use /api/orchestrator/run-once"
    )


@app.on_event("shutdown")
async def shutdown() -> None:
    await close_db()
