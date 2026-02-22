"""Tests for REC-04 API wiring."""

from fastapi.testclient import TestClient

import src.api.app as api_app
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


def test_assets_endpoint_returns_scored_assets_with_limit(monkeypatch):
    async def fake_get_assets(
        db, engagement_id: str, min_score: float = 0.0, limit: int | None = None
    ):
        assert engagement_id == "eng-999"
        assert min_score == 0.5
        assert limit == 25
        return [
            AssetDocument(
                engagement_id=engagement_id,
                asset_type="host",
                ip="203.0.113.10",
                attack_surface_score=0.84,
                score_reasoning="High-risk service exposure.",
            )
        ]

    monkeypatch.setattr(api_app, "get_db", lambda: object())
    monkeypatch.setattr(api_app.mongo, "get_assets", fake_get_assets)

    client = TestClient(api_app.app)
    response = client.get("/api/assets?engagement_id=eng-999&min_score=0.5&limit=25")
    assert response.status_code == 200

    payload = response.json()
    assert payload["engagement_id"] == "eng-999"
    assert payload["count"] == 1
    assert payload["assets"][0]["attack_surface_score"] == 0.84


def test_cors_preflight_for_dashboard_origin():
    client = TestClient(api_app.app)
    response = client.options(
        "/api/assets",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_run_recon_cycle_endpoint_is_non_blocking(monkeypatch):
    api_app._RECON_RUNS.clear()
    events: list[str] = []

    class FakeRecon:
        def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
            events.append("verify")
            return True

    class FakeOrchestrator:
        recon = FakeRecon()

        async def run_cycle(self, scope) -> None:
            events.append("run_cycle")

    def fake_start_recon_task(run_id: str, payload, orchestrator) -> None:
        events.append("start_task")
        api_app._RECON_RUNS[run_id]["status"] = "running"

    monkeypatch.setattr(api_app, "build_orchestrator", lambda: FakeOrchestrator())
    monkeypatch.setattr(api_app, "_start_recon_task", fake_start_recon_task)

    client = TestClient(api_app.app)
    response = client.post(
        "/api/recon/run",
        json={"scope": build_scope_payload(), "on_chain_hash": "abc123"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["engagement_id"] == "eng-999"
    assert payload["status"] == "running"
    assert "run_id" in payload
    assert events == ["verify", "start_task"]

    status_response = client.get(f"/api/recon/run/{payload['run_id']}")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "running"


def test_run_recon_cycle_integrity_failure(monkeypatch):
    api_app._RECON_RUNS.clear()

    class FakeRecon:
        def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
            return False

    class FakeOrchestrator:
        recon = FakeRecon()

    monkeypatch.setattr(api_app, "build_orchestrator", lambda: FakeOrchestrator())

    client = TestClient(api_app.app)
    response = client.post(
        "/api/recon/run",
        json={"scope": build_scope_payload(), "on_chain_hash": "wrong"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Scope integrity check failed."


def test_run_recon_cycle_init_failure_returns_500(monkeypatch):
    api_app._RECON_RUNS.clear()

    def fake_build_orchestrator():
        raise RuntimeError("unexpected init error")

    monkeypatch.setattr(api_app, "build_orchestrator", fake_build_orchestrator)

    client = TestClient(api_app.app)
    response = client.post("/api/recon/run", json={"scope": build_scope_payload()})
    assert response.status_code == 500
    assert response.json()["detail"] == "Failed to initialize orchestrator."
