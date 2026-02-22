"""
Live recon integration test against local Juice Shop scope (no mocks).

Run:
    GEMINI_API_KEY=<key> pytest tests/recon/test_recon_juice_shop_integration.py -v -s -rs
"""

import asyncio
import json
import os
import shutil
import socket
from datetime import datetime, timezone

import pytest

from src.agents.recon.agent import ReconAgent
from src.models.scope import (
    ActiveHours,
    ActiveWindow,
    EngagementConstraints,
    ForbiddenSpec,
    ScopeDocument,
    Targets,
)


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


JUICE_SHOP_AVAILABLE = _port_open("localhost", 3000)
NMAP_AVAILABLE = shutil.which("nmap") is not None
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

juice_shop_required = pytest.mark.skipif(
    not JUICE_SHOP_AVAILABLE,
    reason="Juice Shop not reachable on localhost:3000",
)
nmap_required = pytest.mark.skipif(
    not NMAP_AVAILABLE,
    reason="nmap binary not found in PATH",
)
gemini_required = pytest.mark.skipif(
    not GEMINI_API_KEY,
    reason="GEMINI_API_KEY environment variable not set",
)


@juice_shop_required
@nmap_required
@gemini_required
@pytest.mark.asyncio
async def test_recon_full_cycle_against_juice_shop_scope_no_mocks():
    print("\n[STEP 1/4] Build scope document for local Juice Shop")
    scope = ScopeDocument(
        engagement_id="integ-recon-juice-001",
        customer="JuiceShop Local",
        targets=Targets(
            domains=["localhost"],
            ip_ranges=["127.0.0.1"],
        ),
        forbidden_spec=ForbiddenSpec(),
        constraints=EngagementConstraints(
            active_hours=ActiveHours(
                timezone="UTC",
                windows=[ActiveWindow(days=["mon"], start="00:00", end="23:59")],
            ),
            expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        ),
    )
    print(f"  engagement_id: {scope.engagement_id}")
    print(f"  domains: {scope.targets.domains}")
    print(f"  ip_ranges: {scope.targets.ip_ranges}")

    print("\n[STEP 2/4] Run real ReconAgent (all tools + Gemini scoring)")
    # persist_assets=False avoids requiring a running Mongo instance for this test.
    agent = ReconAgent(gemini_api_key=GEMINI_API_KEY, persist_assets=False)
    assets = await asyncio.wait_for(agent.run(scope), timeout=300)
    print(f"  assets discovered: {len(assets)}")

    print("\n[STEP 3/4] Print full recon output JSON")
    print("=== Recon Assets JSON ===")
    print(json.dumps([a.model_dump(mode='json') for a in assets], indent=2))

    print("\n[STEP 4/4] Basic sanity assertions")
    assert isinstance(assets, list)
    assert len(assets) >= 1
    assert any(
        (
            (a.url and "localhost" in a.url)
            or a.ip in {"127.0.0.1", "localhost"}
            or 3000 in a.open_ports
        )
        for a in assets
    ), "Expected at least one Juice Shop-related asset in recon output"
