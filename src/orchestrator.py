import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.agents.protocols import ExploitProtocol, LateralProtocol, ReconProtocol
from src.db import mongo
from src.models.finding import LateralAgentInput
from src.models.scope import ScopeDocument

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        recon: ReconProtocol,
        exploit: ExploitProtocol,
        lateral: LateralProtocol,
        db: AsyncIOMotorDatabase,
    ) -> None:
        self.recon = recon
        self.exploit = exploit
        self.lateral = lateral
        self.db = db

    async def run_cycle(self, scope: ScopeDocument) -> None:
        # --- Recon ---
        assets = await self.recon.run(scope)
        if not getattr(self.recon, "persists_assets", False):
            await mongo.save_assets(self.db, assets)

        # --- Exploit (only assets above threshold, highest score first) ---
        eligible = sorted(
            [a for a in assets if a.attack_surface_score > 0.5],
            key=lambda a: a.attack_surface_score,
            reverse=True,
        )
        try:
            findings = await self.exploit.run(eligible)
            await mongo.save_findings(self.db, findings)
        except NotImplementedError:
            logger.warning("ExploitAgent is not implemented yet; skipping exploit stage.")
            findings = []

        # --- Lateral (only confirmed multi-asset findings + full asset graph) ---
        multi_asset = [
            f for f in findings if f.exploitable and f.blast_radius == "multi_asset"
        ]
        if not multi_asset:
            return

        try:
            all_assets = await mongo.get_assets(self.db, scope.engagement_id)
            chains = await self.lateral.run(
                LateralAgentInput(findings=multi_asset, asset_graph=all_assets)
            )
            await mongo.save_attack_chains(self.db, chains)
        except NotImplementedError:
            logger.warning("LateralAgent is not implemented yet; skipping lateral stage.")
