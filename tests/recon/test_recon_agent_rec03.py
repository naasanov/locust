"""Tests for REC-03 ReconAgent assembly and scoring flow."""

from datetime import datetime, timezone

import pytest

from src.models.asset import AssetDocument, ExposedFile, ServiceInfo
from src.models.scope import (
    ActiveHours,
    ActiveWindow,
    EngagementConstraints,
    ForbiddenSpec,
    ScopeDocument,
    Targets,
)


class FakeScorer:
    def __init__(self, events: list[str]):
        self.events = events

    async def score_assets(self, assets: list[AssetDocument]) -> list[AssetDocument]:
        self.events.append("score")
        for asset in assets:
            asset.attack_surface_score = 0.77
            asset.score_reasoning = "Scored by fake scorer."
        return assets


def build_scope() -> ScopeDocument:
    return ScopeDocument(
        engagement_id="eng-123",
        customer="Acme",
        targets=Targets(
            domains=["acme.test", "*.acme.test"],
            ip_ranges=["203.0.113.10"],
        ),
        forbidden_spec=ForbiddenSpec(
            forbidden_hosts=["forbidden.acme.test", "10.0.0.1"],
            forbidden_actions=[],
            tier_limit=2,
        ),
        constraints=EngagementConstraints(
            active_hours=ActiveHours(
                timezone="UTC",
                windows=[ActiveWindow(days=["mon"], start="00:00", end="23:59")],
            ),
            cycle_interval_hours=24,
            expires_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            monthly_fee_usdc=500,
        ),
    )


@pytest.mark.asyncio
async def test_recon_agent_rec03_pipeline_and_persistence(monkeypatch):
    from src.agents.recon import agent as recon_agent_module
    from src.agents.recon.agent import ReconAgent

    events: list[str] = []

    async def fake_run_nmap(*, target: str, engagement_id: str, **kwargs):
        events.append("nmap")
        return AssetDocument(
            engagement_id=engagement_id,
            asset_type="host",
            ip="203.0.113.10",
            open_ports=[80],
        )

    async def fake_enumerate_subdomains(*, domain: str, engagement_id: str):
        events.append("subdomain")
        return [
            AssetDocument(
                engagement_id=engagement_id,
                asset_type="subdomain",
                url=f"https://api.{domain}",
                ip="203.0.113.11",
            )
        ]

    async def fake_crawl_endpoints(*, url: str, **kwargs):
        events.append("crawl")
        return ["/", "/admin"]

    async def fake_check_exposed_files(*, base_url: str, **kwargs):
        events.append("exposed")
        return [ExposedFile(path="/.env", size=123)]

    async def fake_censys_lookup(ip: str, api_key: str | None = None):
        events.append("censys")
        return {
            "vulns": ["CVE-2024-0001"],
            "services": [ServiceInfo(port=443, service="nginx", version="1.24")],
            "ports": [443],
            "hostnames": [],
            "os": None,
            "org": None,
            "isp": None,
        }

    async def fake_save_assets(db, assets):
        events.append("save")
        assert len(assets) > 0

    monkeypatch.setattr(recon_agent_module, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(
        recon_agent_module, "enumerate_subdomains", fake_enumerate_subdomains
    )
    monkeypatch.setattr(recon_agent_module, "crawl_endpoints", fake_crawl_endpoints)
    monkeypatch.setattr(
        recon_agent_module, "check_exposed_files", fake_check_exposed_files
    )
    monkeypatch.setattr(recon_agent_module, "censys_lookup", fake_censys_lookup)
    monkeypatch.setattr(recon_agent_module.mongo, "save_assets", fake_save_assets)

    agent = ReconAgent(
        gemini_api_key="test-key",
        db=object(),
        scorer=FakeScorer(events),
        persist_assets=True,
    )

    assets = await agent.run(build_scope())

    assert assets
    assert all(asset.attack_surface_score == 0.77 for asset in assets)
    assert all(asset.score_reasoning == "Scored by fake scorer." for asset in assets)

    # Ensure deterministic stage ordering: collection tools -> score -> save.
    first_score_idx = events.index("score")
    first_save_idx = events.index("save")
    assert first_score_idx < first_save_idx
    assert max(i for i, e in enumerate(events) if e == "nmap") < first_score_idx
    assert max(i for i, e in enumerate(events) if e == "subdomain") < first_score_idx
    assert max(i for i, e in enumerate(events) if e == "crawl") < first_score_idx
    assert max(i for i, e in enumerate(events) if e == "exposed") < first_score_idx
    assert max(i for i, e in enumerate(events) if e == "censys") < first_score_idx


def test_gemini_scorer_parse_scores_handles_valid_and_invalid_payloads():
    from src.agents.recon.scoring.gemini_scorer import GeminiScorer

    valid = """```json
    [{"index": 0, "score": 0.9, "reasoning": "high"}, {"index": 1, "score": 0.2, "reasoning": "low"}]
    ```"""
    parsed_valid = GeminiScorer._parse_scores(valid, expected_count=2)
    assert parsed_valid[0]["score"] == 0.9
    assert parsed_valid[1]["reasoning"] == "low"

    invalid = "not-json"
    parsed_invalid = GeminiScorer._parse_scores(invalid, expected_count=2)
    assert parsed_invalid == {}
