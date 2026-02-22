from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
import os, asyncio, json

load_dotenv()

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = MongoClient(os.getenv("MONGODB_URI"))
db = client[os.getenv("MONGODB_DB", "artaas")]

connected_clients: list[WebSocket] = []

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
