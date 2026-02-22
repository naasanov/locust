"""Tests for REC-04 orchestration wiring behavior."""

from datetime import datetime, timezone

import pytest

from src.models.asset import AssetDocument
from src.models.attack_chain import AttackChain, PivotStep
from src.models.finding import Evidence, FindingDocument
from src.models.scope import (
    ActiveHours,
    ActiveWindow,
    EngagementConstraints,
    ForbiddenSpec,
    ScopeDocument,
    Targets,
)
from src.orchestrator import Orchestrator


def build_scope() -> ScopeDocument:
    return ScopeDocument(
        engagement_id="eng-456",
        customer="Acme",
        targets=Targets(domains=["acme.test"], ip_ranges=["203.0.113.10"]),
        forbidden_spec=ForbiddenSpec(forbidden_hosts=[], forbidden_actions=[], tier_limit=2),
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
async def test_orchestrator_rec04_seeds_and_runs_lateral_when_exploit_unimplemented(monkeypatch):
    events: list[str] = []

    class FakeRecon:
        persists_assets = False

        async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
            events.append("recon")
            return [
                AssetDocument(
                    engagement_id=scope.engagement_id,
                    asset_type="host",
                    ip="203.0.113.10",
                    attack_surface_score=0.9,
                )
            ]

    class FakeExploit:
        async def run(self, assets: list[AssetDocument]) -> list[FindingDocument]:
            events.append("exploit")
            raise NotImplementedError("exploit not ready")

    class FakeLateral:
        async def run(self, input):
            events.append("lateral")
            return []

    async def fake_save_assets(db, assets):
        events.append("save_assets")

    async def fake_save_findings(db, findings):
        events.append("save_findings")

    async def fake_get_assets(db, engagement_id):
        events.append("get_assets")
        return []

    async def fake_save_attack_chains(db, chains):
        events.append("save_attack_chains")

    monkeypatch.setattr("src.orchestrator.mongo.save_assets", fake_save_assets)
    monkeypatch.setattr("src.orchestrator.mongo.save_findings", fake_save_findings)
    monkeypatch.setattr("src.orchestrator.mongo.get_assets", fake_get_assets)
    monkeypatch.setattr("src.orchestrator.mongo.save_attack_chains", fake_save_attack_chains)

    orchestrator = Orchestrator(
        recon=FakeRecon(),
        exploit=FakeExploit(),
        lateral=FakeLateral(),
        db=object(),
    )
    await orchestrator.run_cycle(build_scope())

    assert events == ["recon", "save_assets", "exploit", "save_findings", "get_assets", "lateral", "save_attack_chains"]


@pytest.mark.asyncio
async def test_orchestrator_rec04_runs_lateral_when_multi_asset(monkeypatch):
    events: list[str] = []
    scope = build_scope()

    class FakeRecon:
        persists_assets = True

        async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
            events.append("recon")
            return [
                AssetDocument(
                    engagement_id=scope.engagement_id,
                    asset_type="host",
                    ip="203.0.113.10",
                    attack_surface_score=0.9,
                )
            ]

    class FakeExploit:
        async def run(self, assets: list[AssetDocument]) -> list[FindingDocument]:
            events.append("exploit")
            return [
                FindingDocument(
                    engagement_id=scope.engagement_id,
                    asset_id="asset-1",
                    finding_id="finding-1",
                    vulnerability_class="rce",
                    title="Test Finding",
                    severity="critical",
                    exploitable=True,
                    affected_url="https://acme.test",
                    evidence=Evidence(request="GET /", response_snippet="...", status_code=200),
                    blast_radius="multi_asset",
                )
            ]

    class FakeLateral:
        async def run(self, input) -> list[AttackChain]:
            events.append("lateral")
            return [
                AttackChain(
                    engagement_id=scope.engagement_id,
                    chain_id="chain-1",
                    entry_point_finding_id="finding-1",
                    entry_point="https://acme.test",
                    pivot_path=[PivotStep(step=1, asset="host:203.0.113.10", action="pivot", detail="demo")],
                    blast_radius_score=0.7,
                    blast_radius_summary="demo",
                    gemini_reasoning="demo reasoning",
                )
            ]

    async def fake_save_assets(db, assets):
        events.append("save_assets")

    async def fake_save_findings(db, findings):
        events.append("save_findings")

    async def fake_get_assets(db, engagement_id):
        events.append("get_assets")
        return [
            AssetDocument(
                engagement_id=engagement_id,
                asset_type="host",
                ip="203.0.113.10",
                attack_surface_score=0.9,
            )
        ]

    async def fake_save_attack_chains(db, chains):
        events.append("save_attack_chains")

    monkeypatch.setattr("src.orchestrator.mongo.save_assets", fake_save_assets)
    monkeypatch.setattr("src.orchestrator.mongo.save_findings", fake_save_findings)
    monkeypatch.setattr("src.orchestrator.mongo.get_assets", fake_get_assets)
    monkeypatch.setattr("src.orchestrator.mongo.save_attack_chains", fake_save_attack_chains)

    orchestrator = Orchestrator(
        recon=FakeRecon(),
        exploit=FakeExploit(),
        lateral=FakeLateral(),
        db=object(),
    )
    await orchestrator.run_cycle(scope)

    assert "save_assets" not in events  # recon persists assets itself
    assert events == ["recon", "exploit", "save_findings", "get_assets", "lateral", "save_attack_chains"]
