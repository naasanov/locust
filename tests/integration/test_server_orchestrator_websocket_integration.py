"""
Integration test: run FastAPI server + orchestrator loop and verify websocket events.

This test launches uvicorn as a subprocess, connects to /ws/live, and waits for a
full orchestrator cycle to emit events.
"""

import asyncio
import json
import os
import shutil
import socket
import sys
import time

import httpx
import pytest
from pymongo import MongoClient


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _mongo_reachable(uri: str) -> bool:
    client = MongoClient(uri, serverSelectionTimeoutMS=1500)
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False
    finally:
        client.close()


JUICE_SHOP_AVAILABLE = _port_open("localhost", 3000)
MYSQL_AVAILABLE = _port_open("localhost", 3306)
NMAP_AVAILABLE = shutil.which("nmap") is not None
NUCLEI_AVAILABLE = shutil.which("nuclei") is not None
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGO_AVAILABLE = _mongo_reachable(MONGODB_URI)

juice_shop_required = pytest.mark.skipif(
    not JUICE_SHOP_AVAILABLE,
    reason="Juice Shop not reachable on localhost:3000",
)
mysql_required = pytest.mark.skipif(
    not MYSQL_AVAILABLE,
    reason="MySQL not reachable on localhost:3306",
)
nmap_required = pytest.mark.skipif(
    not NMAP_AVAILABLE,
    reason="nmap binary not found in PATH",
)
nuclei_required = pytest.mark.skipif(
    not NUCLEI_AVAILABLE,
    reason="nuclei binary not found in PATH",
)
gemini_required = pytest.mark.skipif(
    not GEMINI_API_KEY,
    reason="GEMINI_API_KEY environment variable not set",
)
mongo_required = pytest.mark.skipif(
    not MONGO_AVAILABLE,
    reason=f"MongoDB not reachable at {MONGODB_URI}",
)


async def _wait_for_http(url: str, timeout_s: int = 30) -> None:
    deadline = time.time() + timeout_s
    async with httpx.AsyncClient(timeout=2.0) as client:
        while time.time() < deadline:
            try:
                r = await client.get(url)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(0.5)
    raise TimeoutError(f"Timed out waiting for {url}")


@juice_shop_required
@mysql_required
@nmap_required
@nuclei_required
@gemini_required
@mongo_required
@pytest.mark.asyncio
async def test_server_runs_orchestrator_and_emits_websocket_events():
    import websockets

    port = 8012
    health_url = f"http://127.0.0.1:{port}/api/health"
    ws_url = f"ws://127.0.0.1:{port}/ws/live"

    env = os.environ.copy()
    env["ORCHESTRATOR_ENABLED"] = "true"
    env["ORCHESTRATOR_INTERVAL_SECONDS"] = "3600"
    env["ORCHESTRATOR_STARTUP_DELAY_SECONDS"] = "2"
    env["ENGAGEMENT_ID"] = "integ-server-ws-001"
    env["TARGET_URL"] = ""
    env["TARGET_IP"] = "127.0.0.1"
    env["LOG_LEVEL"] = "INFO"
    # Use broader profile for closer-to-real exploit behavior.
    env["NUCLEI_TAGS"] = "exposure,misconfig,api,headers"
    env["NUCLEI_SEVERITY"] = "info,low,medium,high,critical"
    env["NUCLEI_PROCESS_TIMEOUT_S"] = "300"

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "uvicorn",
        "server.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "info",
        env=env,
    )

    try:
        await _wait_for_http(health_url, timeout_s=40)

        events: list[dict] = []
        print(f"\nConnected to websocket: {ws_url}")
        async with websockets.connect(ws_url, open_timeout=10) as ws:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=420)
                payload = json.loads(raw)
                print("WS EVENT:", json.dumps(payload))
                if "event" in payload:
                    events.append(payload)
                if payload.get("event") == "cycle_complete":
                    break

        names = [e.get("event") for e in events]
        required = {
            "cycle_started",
            "recon_complete",
            "exploit_complete",
            "lateral_complete",
            "cycle_complete",
        }
        missing = required - set(names)
        assert not missing, f"Missing required websocket events: {sorted(missing)}"
        cycle_complete = next(e for e in events if e.get("event") == "cycle_complete")
        assert cycle_complete.get("skipped") is None
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
