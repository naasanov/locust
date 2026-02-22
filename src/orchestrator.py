import os
import uuid
from collections.abc import Awaitable, Callable

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.agents.protocols import ExploitProtocol, LateralProtocol, ReconProtocol
from src.config import get_settings
from src.db import mongo
from src.models.finding import Evidence, FindingDocument, LateralAgentInput
from src.integrations.github_issues import create_issues_for_chains
from src.models.scope import ScopeDocument

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
                print(f"[orchestrator] WARNING: broadcast failed for event={message.get('event')}")

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
            print("[orchestrator] WARNING: ExploitAgent is not implemented; skipping exploit stage.")
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
            seeded = self._build_demo_seed_finding(scope, findings, assets)
            if seeded is not None:
                findings.append(seeded)
                await mongo.save_findings(self.db, [seeded])
                multi_asset = [seeded]
                await self._emit({
                    "event": "demo_seeded",
                    "engagement_id": scope.engagement_id,
                    "finding_id": seeded.finding_id,
                    "affected_url": seeded.affected_url,
                })
                print(
                    "[orchestrator] WARNING: Demo seed injected "
                    f"for engagement={scope.engagement_id} finding_id={seeded.finding_id}"
                )
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
            print("[orchestrator] WARNING: LateralAgent is not implemented; skipping lateral stage.")
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
            print(
                "[orchestrator] GitHub issue step: "
                f"repo_url={scope.github_repo_url} chain_count={len(chains)} token_present={bool(token)}"
            )
            if token:
                issue_urls = await create_issues_for_chains(
                    chains=chains,
                    repo_url=scope.github_repo_url,
                    github_token=token,
                )
                print(
                    "[orchestrator] GitHub issue step complete: "
                    f"created={len(issue_urls)} repo_url={scope.github_repo_url}"
                )
                if not issue_urls:
                    print(
                        "[orchestrator] WARNING: GitHub issue step produced no issues "
                        f"(repo={scope.github_repo_url}, chains={len(chains)}). "
                        "See github_issues prints above for API details."
                    )
                await self._emit({
                    "event": "github_issues_created",
                    "engagement_id": scope.engagement_id,
                    "issue_urls": issue_urls,
                })
            else:
                print(
                    "[orchestrator] WARNING: github_repo_url is set but GITHUB_TOKEN is empty; "
                    "skipping issue creation."
                )
        else:
            print("[orchestrator] GitHub issue step skipped: scope.github_repo_url is empty")

        await self._emit({"event": "cycle_complete", "engagement_id": scope.engagement_id})

    @staticmethod
    def _build_demo_seed_finding(
        scope: ScopeDocument,
        findings: list[FindingDocument],
        assets,
    ) -> FindingDocument | None:
        seed_url = os.getenv("ORCHESTRATOR_DEMO_SEED_URL", "http://127.0.0.1:8000/.env")
        snippet = os.getenv(
            "ORCHESTRATOR_DEMO_SEED_SNIPPET",
            "DB_HOST=localhost\nDB_USER=juice_admin\nDB_PASSWORD=s3cr3tpass!\nNODE_ENV=production\n",
        )
        parsed_status = os.getenv("ORCHESTRATOR_DEMO_SEED_STATUS", "200")
        try:
            status_code = int(parsed_status)
        except ValueError:
            status_code = 200

        asset_id = ""
        if assets:
            asset_id = getattr(assets[0], "asset_id", "") or ""
        if not asset_id and findings:
            asset_id = findings[0].asset_id
        if not asset_id:
            return None

        return FindingDocument(
            engagement_id=scope.engagement_id,
            asset_id=asset_id,
            finding_id=f"demo-seed-{uuid.uuid4()}",
            vulnerability_class="credential_exposure",
            title="Demo Seed: Exposed .env file with DB credentials",
            severity="critical",
            exploitable=True,
            affected_url=seed_url,
            evidence=Evidence(
                request="GET /.env HTTP/1.1\nHost: 127.0.0.1:8000",
                response_snippet=snippet,
                status_code=status_code,
            ),
            blast_radius="multi_asset",
            gemini_reasoning="[demo-seed] Injected by orchestrator fallback",
        )
