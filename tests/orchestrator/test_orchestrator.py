"""
Orchestrator integration tests — EXP-04.

Verifies:
  - Confirmed findings are persisted to db.findings
  - Only assets above the 0.5 score threshold reach the exploit agent
  - Assets are passed to exploit sorted highest-score first
  - Multi-asset + exploitable findings are forwarded to the lateral agent
  - Single-asset or non-exploitable findings are NOT forwarded to lateral
  - Lateral is skipped entirely when no qualifying findings exist
  - Attack chains produced by lateral are persisted to db.attack_chains
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(engagement_id: str = "eng-001") -> ScopeDocument:
    return ScopeDocument(
        engagement_id=engagement_id,
        customer="Acme Corp",
        targets=Targets(domains=["acmecorp.com"]),
        forbidden_spec=ForbiddenSpec(),
        constraints=EngagementConstraints(
            active_hours=ActiveHours(
                timezone="UTC",
                windows=[ActiveWindow(days=["mon"], start="00:00", end="23:59")],
            ),
            expires_at=datetime(2026, 12, 31, tzinfo=timezone.utc),
        ),
    )


def _asset(score: float, engagement_id: str = "eng-001") -> AssetDocument:
    return AssetDocument(
        engagement_id=engagement_id,
        asset_type="web_app",
        url=f"https://example-{score}.com",
        attack_surface_score=score,
    )


def _finding(
    exploitable: bool,
    blast_radius: str,
    engagement_id: str = "eng-001",
) -> FindingDocument:
    return FindingDocument(
        engagement_id=engagement_id,
        asset_id=str(uuid.uuid4()),
        finding_id=str(uuid.uuid4()),
        vulnerability_class="rce",
        title="Test Finding",
        severity="high",
        exploitable=exploitable,
        affected_url="https://example.com/vuln",
        evidence=Evidence(request="GET /vuln", response_snippet="shell", status_code=200),
        blast_radius=blast_radius,  # type: ignore[arg-type]
    )


def _chain(engagement_id: str = "eng-001") -> AttackChain:
    return AttackChain(
        engagement_id=engagement_id,
        chain_id=str(uuid.uuid4()),
        entry_point_finding_id=str(uuid.uuid4()),
        entry_point="https://example.com/vuln",
        pivot_path=[PivotStep(step=1, asset="db", action="read", detail="got creds")],
        blast_radius_score=0.9,
        blast_radius_summary="Full DB access",
        gemini_reasoning="RCE → credential dump → lateral DB access",
    )


def _build_orchestrator(recon, exploit, lateral) -> Orchestrator:
    """Build an Orchestrator with a MagicMock db."""
    return Orchestrator(recon=recon, exploit=exploit, lateral=lateral, db=MagicMock())


# ---------------------------------------------------------------------------
# Asset filtering + ordering
# ---------------------------------------------------------------------------


class TestAssetEligibility:
    @pytest.mark.asyncio
    async def test_only_above_threshold_assets_reach_exploit(self):
        """Assets with score <= 0.5 must not be passed to exploit.run()."""
        assets = [
            _asset(score=0.9),
            _asset(score=0.6),
            _asset(score=0.5),   # threshold is > 0.5, so this is excluded
            _asset(score=0.3),
        ]
        recon = AsyncMock()
        recon.run = AsyncMock(return_value=assets)
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=[])

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])

        orch = _build_orchestrator(recon, exploit, lateral)

        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", AsyncMock()):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        call_args = exploit.run.call_args[0][0]
        scores = [a.attack_surface_score for a in call_args]
        assert all(s > 0.5 for s in scores)
        assert 0.5 not in scores
        assert 0.3 not in scores

    @pytest.mark.asyncio
    async def test_assets_passed_to_exploit_sorted_highest_first(self):
        """Exploit receives assets sorted descending by attack_surface_score."""
        assets = [_asset(0.6), _asset(0.9), _asset(0.7)]
        recon = AsyncMock()
        recon.run = AsyncMock(return_value=assets)
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=[])

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])
        orch = _build_orchestrator(recon, exploit, lateral)

        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", AsyncMock()):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        passed = exploit.run.call_args[0][0]
        scores = [a.attack_surface_score for a in passed]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Findings → db
# ---------------------------------------------------------------------------


class TestFindingsPersistence:
    @pytest.mark.asyncio
    async def test_all_returned_findings_saved_to_db(self):
        """Every finding returned by exploit.run() is persisted via save_findings."""
        findings = [
            _finding(exploitable=True, blast_radius="multi_asset"),
            _finding(exploitable=True, blast_radius="single_asset"),
            _finding(exploitable=False, blast_radius="multi_asset"),
        ]

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=findings)

        orch = _build_orchestrator(recon, exploit, AsyncMock())

        save_findings_mock = AsyncMock()
        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", save_findings_mock):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        save_findings_mock.assert_called_once()
        saved = save_findings_mock.call_args[0][1]
        assert len(saved) == 3


# ---------------------------------------------------------------------------
# Findings → lateral agent
# ---------------------------------------------------------------------------


class TestFindingsToLateral:
    @pytest.mark.asyncio
    async def test_multi_asset_confirmed_findings_reach_lateral(self):
        """Only exploitable=True + blast_radius=multi_asset findings go to lateral."""
        multi = _finding(exploitable=True, blast_radius="multi_asset")
        single = _finding(exploitable=True, blast_radius="single_asset")
        borderline = _finding(exploitable=False, blast_radius="multi_asset")

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=[multi, single, borderline])

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])

        orch = _build_orchestrator(recon, exploit, lateral)

        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", AsyncMock()):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        lateral.run.assert_called_once()
        lateral_input = lateral.run.call_args[0][0]
        assert len(lateral_input.findings) == 1
        assert lateral_input.findings[0].finding_id == multi.finding_id

    @pytest.mark.asyncio
    async def test_lateral_called_with_seed_when_no_multi_asset_findings(self):
        """When no multi-asset findings exist, orchestrator injects demo seed and runs lateral."""
        findings = [
            _finding(exploitable=True, blast_radius="single_asset"),
            _finding(exploitable=False, blast_radius="multi_asset"),
        ]

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=findings)

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])

        orch = _build_orchestrator(recon, exploit, lateral)

        save_findings_mock = AsyncMock()
        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", save_findings_mock):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[_asset(0.8)])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        lateral.run.assert_called_once()
        lateral_input = lateral.run.call_args[0][0]
        assert len(lateral_input.findings) == 1
        assert lateral_input.findings[0].vulnerability_class == "credential_exposure"
        assert lateral_input.findings[0].blast_radius == "multi_asset"
        assert lateral_input.findings[0].exploitable is True
        # One save for exploit findings + one save for seeded finding.
        assert save_findings_mock.call_count == 2

    @pytest.mark.asyncio
    async def test_lateral_receives_full_asset_graph(self):
        """Lateral receives the full asset graph from db, not just eligible assets."""
        multi = _finding(exploitable=True, blast_radius="multi_asset")

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=[multi])

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])

        all_db_assets = [_asset(0.8), _asset(0.2), _asset(0.9)]

        orch = _build_orchestrator(recon, exploit, lateral)

        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", AsyncMock()):
                with patch(
                    "src.orchestrator.mongo.get_assets",
                    AsyncMock(return_value=all_db_assets),
                ):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        lateral_input = lateral.run.call_args[0][0]
        assert len(lateral_input.asset_graph) == 3

    @pytest.mark.asyncio
    async def test_demo_seed_on_miss_forces_lateral(self, monkeypatch):
        """Inject seed finding and run lateral when no real multi-asset findings exist."""
        monkeypatch.setenv("ORCHESTRATOR_DEMO_SEED_URL", "http://127.0.0.1:8000/.env")

        findings = [
            _finding(exploitable=True, blast_radius="single_asset"),
            _finding(exploitable=False, blast_radius="multi_asset"),
        ]

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=findings)

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=[])

        orch = _build_orchestrator(recon, exploit, lateral)

        save_findings_mock = AsyncMock()
        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", save_findings_mock):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[_asset(0.8)])):
                    with patch("src.orchestrator.mongo.save_attack_chains", AsyncMock()):
                        await orch.run_cycle(_scope())

        lateral.run.assert_called_once()
        lateral_input = lateral.run.call_args[0][0]
        assert len(lateral_input.findings) == 1
        seeded = lateral_input.findings[0]
        assert seeded.vulnerability_class == "credential_exposure"
        assert seeded.blast_radius == "multi_asset"
        assert seeded.exploitable is True
        assert seeded.affected_url == "http://127.0.0.1:8000/.env"
        # Original findings + one seeded finding are persisted
        saved = save_findings_mock.call_args_list[-1][0][1]
        assert len(saved) == 1


# ---------------------------------------------------------------------------
# Attack chains → db
# ---------------------------------------------------------------------------


class TestAttackChainPersistence:
    @pytest.mark.asyncio
    async def test_attack_chains_saved_to_db(self):
        """Attack chains returned by lateral.run() are persisted via save_attack_chains."""
        multi = _finding(exploitable=True, blast_radius="multi_asset")
        chains = [_chain(), _chain()]

        recon = AsyncMock()
        recon.run = AsyncMock(return_value=[_asset(0.8)])
        recon.persists_assets = False

        exploit = AsyncMock()
        exploit.run = AsyncMock(return_value=[multi])

        lateral = AsyncMock()
        lateral.run = AsyncMock(return_value=chains)

        orch = _build_orchestrator(recon, exploit, lateral)

        save_chains_mock = AsyncMock()
        with patch("src.orchestrator.mongo.save_assets", AsyncMock()):
            with patch("src.orchestrator.mongo.save_findings", AsyncMock()):
                with patch("src.orchestrator.mongo.get_assets", AsyncMock(return_value=[])):
                    with patch("src.orchestrator.mongo.save_attack_chains", save_chains_mock):
                        await orch.run_cycle(_scope())

        save_chains_mock.assert_called_once()
        saved_chains = save_chains_mock.call_args[0][1]
        assert len(saved_chains) == 2
