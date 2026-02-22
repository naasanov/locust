from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from src.models.asset import AssetDocument, ServiceInfo
from src.models.attack_chain import AttackChain, PivotStep, SensitiveStore
from src.models.finding import Evidence, FindingDocument, LateralAgentInput
from src.models.scope import ScopeDocument

logger = logging.getLogger(__name__)


class MockReconAgent:
    """Deterministic recon stub for server/dev smoke runs."""

    persists_assets = False

    def __init__(self, event_emitter: Callable[[dict], Awaitable[None]] | None = None):
        self._event_emitter = event_emitter

    async def _emit(self, message: dict) -> None:
        if self._event_emitter is None:
            return
        try:
            await self._event_emitter(message)
        except Exception:
            logger.debug("MockRecon event emit failed", exc_info=True)

    async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
        logger.info(
            "MockReconAgent starting for engagement %s",
            scope.engagement_id,
        )
        host = "127.0.0.1"
        if scope.targets.ip_ranges:
            host = scope.targets.ip_ranges[0]
        elif scope.targets.domains:
            host = scope.targets.domains[0]

        asset = AssetDocument(
            engagement_id=scope.engagement_id,
            asset_type="web_app",
            ip=host if host.replace(".", "").isdigit() else None,
            url=f"http://{host}:3000",
            open_ports=[3000, 3306, 8000],
            services=[
                ServiceInfo(port=3000, service="http"),
                ServiceInfo(port=3306, service="mysql"),
                ServiceInfo(port=8000, service="http"),
            ],
            attack_surface_score=0.95,
            score_reasoning="[mock] seeded high-value demo target",
        )
        await self._emit(
            {
                "event": "mock_recon_generated_assets",
                "engagement_id": scope.engagement_id,
                "assets": [asset.model_dump(mode="json")],
            }
        )
        logger.info(
            "MockReconAgent produced %d asset(s) for %s",
            1,
            scope.engagement_id,
        )
        return [asset]


class MockExploitAgent:
    """Deterministic exploit stub that emits one credential exposure finding."""

    def __init__(self, event_emitter: Callable[[dict], Awaitable[None]] | None = None):
        self._event_emitter = event_emitter

    async def _emit(self, message: dict) -> None:
        if self._event_emitter is None:
            return
        try:
            await self._event_emitter(message)
        except Exception:
            logger.debug("MockExploit event emit failed", exc_info=True)

    async def run(self, assets: list[AssetDocument]) -> list[FindingDocument]:
        logger.info("MockExploitAgent starting with %d asset(s)", len(assets))
        if not assets:
            logger.info("MockExploitAgent skipped: no eligible assets")
            return []
        asset = assets[0]
        finding = FindingDocument(
            engagement_id=asset.engagement_id,
            asset_id=asset.asset_id,
            finding_id=f"mock-finding-{uuid.uuid4()}",
            vulnerability_class="credential_exposure",
            title="Mock: Exposed .env file with DB credentials",
            severity="critical",
            exploitable=True,
            affected_url="http://127.0.0.1:8000/.env",
            evidence=Evidence(
                request="GET /.env HTTP/1.1\nHost: 127.0.0.1:8000",
                response_snippet=(
                    "DB_HOST=localhost\nDB_USER=juice_admin\n"
                    "DB_PASSWORD=s3cr3tpass!\nNODE_ENV=production\n"
                ),
                status_code=200,
            ),
            blast_radius="multi_asset",
            gemini_reasoning="[mock] deterministic exploit finding",
        )
        await self._emit(
            {
                "event": "mock_exploit_generated_findings",
                "engagement_id": asset.engagement_id,
                "findings": [finding.model_dump(mode="json")],
            }
        )
        logger.info(
            "MockExploitAgent produced %d finding(s) for engagement %s",
            1,
            asset.engagement_id,
        )
        return [finding]


class MockLateralAgent:
    """Deterministic lateral stub that returns one chain from the first finding."""

    def __init__(self, event_emitter: Callable[[dict], Awaitable[None]] | None = None):
        self._event_emitter = event_emitter

    async def _emit(self, message: dict) -> None:
        if self._event_emitter is None:
            return
        try:
            await self._event_emitter(message)
        except Exception:
            logger.debug("MockLateral event emit failed", exc_info=True)

    async def run(self, input: LateralAgentInput) -> list[AttackChain]:
        logger.info(
            "MockLateralAgent starting with %d finding(s) and %d assets",
            len(input.findings),
            len(input.asset_graph),
        )
        if not input.findings:
            logger.info("MockLateralAgent skipped: no findings provided")
            return []
        finding = input.findings[0]
        chain = AttackChain(
            engagement_id=finding.engagement_id,
            chain_id=f"mock-chain-{uuid.uuid4()}",
            entry_point_finding_id=finding.finding_id,
            entry_point=finding.affected_url,
            pivot_path=[
                PivotStep(
                    step=1,
                    asset="127.0.0.1",
                    action="Extract Credentials",
                    detail="Parsed DB_USER/DB_PASSWORD from exposed .env",
                    mitre="T1552.001",
                ),
                PivotStep(
                    step=2,
                    asset="127.0.0.1:3306",
                    action="Database Access",
                    detail="Used leaked credentials to access MySQL",
                    mitre="T1078",
                ),
            ],
            reachable_sensitive_stores=[
                SensitiveStore(
                    type="database",
                    asset="127.0.0.1:3306",
                    contents="juice_db",
                    credentials_used="juice_admin:s3cr3tpass!",
                )
            ],
            blast_radius_score=0.8,
            blast_radius_summary="Mock chain shows compromise path from web exposure to DB.",
            gemini_reasoning="[mock] deterministic lateral chain",
            mitre_techniques=["T1552.001", "T1078", "T1530"],
            discovered_at=datetime.now(timezone.utc),
        )
        await self._emit(
            {
                "event": "mock_lateral_generated_chains",
                "engagement_id": finding.engagement_id,
                "chains": [chain.model_dump(mode="json")],
            }
        )
        logger.info(
            "MockLateralAgent produced %d chain(s) for engagement %s",
            1,
            finding.engagement_id,
        )
        return [chain]
