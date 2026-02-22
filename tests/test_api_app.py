"""Tests for REC-04 API wiring."""

from fastapi.testclient import TestClient

from src.api.app import app
from src.models.asset import AssetDocument


def build_scope_payload() -> dict:
    return {
        "engagement_id": "eng-999",
        "customer": "Acme",
        "targets": {
            "domains": ["acme.test"],
            "ip_ranges": ["203.0.113.10"],
            "cloud_accounts": [],
        },
        "forbidden_spec": {
            "forbidden_hosts": [],
            "forbidden_actions": [],
            "tier_limit": 2,
        },
        "constraints": {
            "active_hours": {
                "timezone": "UTC",
                "windows": [{"days": ["mon"], "start": "00:00", "end": "23:59"}],
            },
            "cycle_interval_hours": 24,
            "expires_at": "2026-06-01T00:00:00Z",
            "monthly_fee_usdc": 500,
        },
    }


def test_assets_endpoint_returns_scored_assets(monkeypatch):
    async def fake_get_assets(db, engagement_id: str, min_score: float = 0.0):
        return [
            AssetDocument(
                engagement_id=engagement_id,
                asset_type="host",
                ip="203.0.113.10",
                attack_surface_score=0.84,
                score_reasoning="High-risk service exposure.",
            )
        ]

    monkeypatch.setattr("src.api.app.get_db", lambda: object())
    monkeypatch.setattr("src.api.app.mongo.get_assets", fake_get_assets)

    client = TestClient(app)
    response = client.get("/api/assets?engagement_id=eng-999&min_score=0.5")
    assert response.status_code == 200

    payload = response.json()
    assert payload["engagement_id"] == "eng-999"
    assert payload["count"] == 1
    assert payload["assets"][0]["attack_surface_score"] == 0.84


def test_run_recon_cycle_endpoint(monkeypatch):
    events: list[str] = []

    class FakeRecon:
        def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
            events.append("verify")
            return True

    class FakeOrchestrator:
        recon = FakeRecon()

        async def run_cycle(self, scope) -> None:
            events.append("run_cycle")

    async def fake_get_assets(db, engagement_id: str, min_score: float = 0.0):
        return [
            AssetDocument(
                engagement_id=engagement_id,
                asset_type="host",
                ip="203.0.113.10",
                attack_surface_score=0.91,
            )
        ]

    monkeypatch.setattr("src.api.app.build_orchestrator", lambda: FakeOrchestrator())
    monkeypatch.setattr("src.api.app.get_db", lambda: object())
    monkeypatch.setattr("src.api.app.mongo.get_assets", fake_get_assets)

    client = TestClient(app)
    response = client.post(
        "/api/recon/run",
        json={"scope": build_scope_payload(), "on_chain_hash": "abc123"},
    )
    assert response.status_code == 200
    assert response.json() == {"engagement_id": "eng-999", "assets_discovered": 1}
    assert events == ["verify", "run_cycle"]


def test_run_recon_cycle_integrity_failure(monkeypatch):
    class FakeRecon:
        def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
            return False

    class FakeOrchestrator:
        recon = FakeRecon()

        async def run_cycle(self, scope) -> None:
            raise AssertionError("run_cycle should not execute when integrity check fails")

    monkeypatch.setattr("src.api.app.build_orchestrator", lambda: FakeOrchestrator())
    monkeypatch.setattr("src.api.app.get_db", lambda: object())

    client = TestClient(app)
    response = client.post(
        "/api/recon/run",
        json={"scope": build_scope_payload(), "on_chain_hash": "wrong"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Scope integrity check failed."
