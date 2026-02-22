import logging
from collections.abc import Awaitable, Callable

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.agents.protocols import ExploitProtocol, LateralProtocol, ReconProtocol
from src.config import get_settings
from src.db import mongo
from src.integrations.github_issues import create_issues_for_chains
from src.models.finding import LateralAgentInput
from src.models.scope import ScopeDocument

logger = logging.getLogger(__name__)

BroadcastFn = Callable[[dict], Awaitable[None]]


class Orchestrator:
    def __init__(
        self,
        recon: ReconProtocol,
        exploit: ExploitProtocol,
        lateral: LateralProtocol,
        db: AsyncIOMotorDatabase,
        broadcast: BroadcastFn | None = None,
    ) -> None:
        self.recon = recon
        self.exploit = exploit
        self.lateral = lateral
        self.db = db
        self._broadcast = broadcast

    async def _emit(self, message: dict) -> None:
        if self._broadcast is not None:
            try:
                await self._broadcast(message)
            except Exception:
                logger.warning("broadcast failed for event %s", message.get("event"))

    async def run_cycle(self, scope: ScopeDocument) -> None:
        await self._emit({"event": "cycle_started", "engagement_id": scope.engagement_id})

        # --- Recon ---
        assets = await self.recon.run(scope)
        if not getattr(self.recon, "persists_assets", False):
            await mongo.save_assets(self.db, assets)
        await self._emit({
            "event": "recon_complete",
            "engagement_id": scope.engagement_id,
            "asset_count": len(assets),
        })

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
        await self._emit({
            "event": "exploit_complete",
            "engagement_id": scope.engagement_id,
            "finding_count": len(findings),
        })

        # --- Lateral (only confirmed multi-asset findings + full asset graph) ---
        multi_asset = [
            f for f in findings if f.exploitable and f.blast_radius == "multi_asset"
        ]
        if not multi_asset:
            await self._emit({
                "event": "cycle_complete",
                "engagement_id": scope.engagement_id,
                "skipped": "lateral",
            })
            return

        all_assets = await mongo.get_assets(self.db, scope.engagement_id)
        try:
            chains = await self.lateral.run(
                LateralAgentInput(findings=multi_asset, asset_graph=all_assets)
            )
        except NotImplementedError:
            logger.warning("LateralAgent is not implemented yet; skipping lateral stage.")
            await self._emit({
                "event": "cycle_complete",
                "engagement_id": scope.engagement_id,
                "skipped": "lateral",
            })
            return

        await mongo.save_attack_chains(self.db, chains)
        await self._emit({
            "event": "lateral_complete",
            "engagement_id": scope.engagement_id,
            "chain_count": len(chains),
        })

        # --- GitHub Issues (optional — only when a repo URL is provided) ---
        if scope.github_repo_url:
            token = get_settings().GITHUB_TOKEN
            if token:
                issue_urls = await create_issues_for_chains(
                    chains=chains,
                    repo_url=scope.github_repo_url,
                    github_token=token,
                )
                await self._emit({
                    "event": "github_issues_created",
                    "engagement_id": scope.engagement_id,
                    "issue_urls": issue_urls,
                })
            else:
                logger.warning(
                    "github_repo_url is set but GITHUB_TOKEN is empty; skipping issue creation."
                )

        await self._emit({"event": "cycle_complete", "engagement_id": scope.engagement_id})
