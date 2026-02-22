"""Main Recon Agent implementation."""

import hashlib
import json
import logging
from urllib.parse import urlparse

from motor.motor_asyncio import AsyncIOMotorDatabase
from src.db import mongo
from src.db.mongo import get_db
from src.models.asset import AssetDocument
from src.models.scope import ScopeDocument
from .tools import (
    run_nmap,
    enumerate_subdomains,
    crawl_endpoints,
    check_exposed_files,
    shodan_lookup,
)
from .scoring import GeminiScorer

logger = logging.getLogger(__name__)


class ReconAgent:
    """
    Deterministic reconnaissance agent.

    Architecture:
    - All five tools run every time, unconditionally, in fixed order
    - No LLM in the collection loop
    - Gemini Flash called ONCE at the end to score and prioritize

    Pipeline Order:
    1. run_nmap - Port scanning and service detection
    2. enumerate_subdomains - Subdomain discovery
    3. crawl_endpoints - HTTP endpoint crawling
    4. check_exposed_files - Sensitive file detection
    5. shodan_lookup - Vulnerability enrichment
    6. gemini_scorer - Attack surface scoring (LLM)
    """

    persists_assets = True

    def __init__(
        self,
        gemini_api_key: str | None = None,
        shodan_api_key: str | None = None,
        db: AsyncIOMotorDatabase | None = None,
        scorer: GeminiScorer | None = None,
        persist_assets: bool = True,
    ):
        """
        Initialize the Recon Agent.

        Args:
            gemini_api_key: API key for Gemini Flash scoring
            shodan_api_key: API key for Shodan lookups
        """
        self.gemini_api_key = gemini_api_key
        self._scorer = scorer
        self.shodan_api_key = shodan_api_key
        self.db = db or get_db()
        self.persists_assets = persist_assets

    @property
    def scorer(self) -> GeminiScorer:
        if self._scorer is None:
            self._scorer = GeminiScorer(api_key=self.gemini_api_key)
        return self._scorer

    def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
        """
        Verify scope document against on-chain hash.

        Args:
            scope_doc: Scope document from MongoDB
            on_chain_hash: SHA-256 hash from Solana engagement account

        Returns:
            True if hashes match, False otherwise
        """
        doc_json = json.dumps(scope_doc, sort_keys=True, separators=(",", ":"))
        computed_hash = hashlib.sha256(doc_json.encode()).hexdigest()

        if computed_hash != on_chain_hash:
            logger.error(
                f"Scope integrity check failed! "
                f"Computed: {computed_hash}, On-chain: {on_chain_hash}"
            )
            return False

        logger.info("Scope integrity verified against on-chain hash")
        return True

    async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
        """
        Run a complete recon cycle.

        All five tools run deterministically in order.
        Gemini scores at the end.

        Args:
            scope: Verified scope document

        Returns:
            List of scored AssetDocuments
        """
        logger.info(f"Starting recon cycle for engagement {scope.engagement_id}")

        assets_by_key: dict[str, AssetDocument] = {}
        domains = self._normalized_domains(scope)
        nmap_targets = self._nmap_targets(scope, domains)

        # 1) nmap
        for target in nmap_targets:
            if self._is_forbidden_host(scope, target):
                continue
            asset = await run_nmap(
                target=target,
                engagement_id=scope.engagement_id,
            )
            if asset is not None:
                self._merge_asset(assets_by_key, asset)

        # 2) subdomain enumeration
        for domain in domains:
            if self._is_forbidden_host(scope, domain):
                continue
            discovered = await enumerate_subdomains(
                domain=domain,
                engagement_id=scope.engagement_id,
            )
            for asset in discovered:
                if self._is_forbidden_asset(scope, asset):
                    continue
                self._merge_asset(assets_by_key, asset)

        # 3) endpoint crawl
        for url in self._crawl_urls(domains, assets_by_key):
            if self._is_forbidden_url(scope, url):
                continue
            endpoints = await crawl_endpoints(url=url)
            if not endpoints:
                continue
            web_asset = self._get_or_create_web_asset(
                assets_by_key=assets_by_key,
                engagement_id=scope.engagement_id,
                url=url,
            )
            web_asset.endpoints = sorted(set(web_asset.endpoints) | set(endpoints))

        # 4) exposed files
        for url in self._web_urls(assets_by_key):
            if self._is_forbidden_url(scope, url):
                continue
            exposed = await check_exposed_files(base_url=url)
            if not exposed:
                continue
            web_asset = self._get_or_create_web_asset(
                assets_by_key=assets_by_key,
                engagement_id=scope.engagement_id,
                url=url,
            )
            existing = {f.path: f for f in web_asset.exposed_files}
            for file in exposed:
                existing[file.path] = file
            web_asset.exposed_files = [existing[p] for p in sorted(existing.keys())]

        # 5) shodan lookup
        for asset in assets_by_key.values():
            if not asset.ip or self._is_forbidden_host(scope, asset.ip):
                continue
            enrichment = await shodan_lookup(asset.ip, api_key=self.shodan_api_key)

            asset.shodan_vulns = sorted(
                set(asset.shodan_vulns) | set(enrichment.get("vulns", []))
            )
            asset.open_ports = sorted(
                set(asset.open_ports) | set(enrichment.get("ports", []))
            )
            current_services = {
                (service.port, service.service, service.version): service
                for service in asset.services
            }
            for service in enrichment.get("services", []):
                key = (service.port, service.service, service.version)
                current_services[key] = service
            asset.services = sorted(
                current_services.values(),
                key=lambda s: (s.port, s.service, s.version or ""),
            )

        # 6) Gemini score once at the end
        collected_assets = list(assets_by_key.values())
        scored_assets = await self.scorer.score_assets(collected_assets)

        if self.persists_assets:
            await mongo.save_assets(self.db, scored_assets)

        logger.info(
            f"Recon cycle complete for {scope.engagement_id}: {len(scored_assets)} assets"
        )
        return scored_assets

    @staticmethod
    def _asset_key(asset: AssetDocument) -> str:
        if asset.ip:
            return f"ip:{asset.ip}"
        if asset.url:
            return f"url:{asset.url.lower().rstrip('/')}"
        return f"asset:{asset.asset_type}:{id(asset)}"

    @classmethod
    def _merge_asset(cls, assets_by_key: dict[str, AssetDocument], asset: AssetDocument) -> None:
        key = cls._asset_key(asset)
        current = assets_by_key.get(key)
        if current is None:
            assets_by_key[key] = asset
            return

        current.asset_type = "web_app" if "web_app" in {current.asset_type, asset.asset_type} else current.asset_type
        current.url = current.url or asset.url
        current.ip = current.ip or asset.ip
        current.open_ports = sorted(set(current.open_ports) | set(asset.open_ports))
        current.endpoints = sorted(set(current.endpoints) | set(asset.endpoints))
        current.shodan_vulns = sorted(set(current.shodan_vulns) | set(asset.shodan_vulns))

        services = {
            (service.port, service.service, service.version): service
            for service in current.services
        }
        for service in asset.services:
            services[(service.port, service.service, service.version)] = service
        current.services = sorted(
            services.values(), key=lambda s: (s.port, s.service, s.version or "")
        )

        exposed = {f.path: f for f in current.exposed_files}
        for file in asset.exposed_files:
            exposed[file.path] = file
        current.exposed_files = [exposed[p] for p in sorted(exposed.keys())]

    @staticmethod
    def _normalized_domains(scope: ScopeDocument) -> list[str]:
        normalized: list[str] = []
        for domain in scope.targets.domains:
            d = domain.strip().lower()
            if d.startswith("*."):
                d = d[2:]
            if d and d not in normalized:
                normalized.append(d)
        return normalized

    @staticmethod
    def _nmap_targets(scope: ScopeDocument, domains: list[str]) -> list[str]:
        targets: list[str] = []
        for ip_or_range in scope.targets.ip_ranges:
            value = ip_or_range.strip()
            if value and value not in targets:
                targets.append(value)
        for domain in domains:
            if domain not in targets:
                targets.append(domain)
        return targets

    @staticmethod
    def _crawl_urls(domains: list[str], assets_by_key: dict[str, AssetDocument]) -> list[str]:
        urls: set[str] = {f"https://{domain}" for domain in domains}
        urls.update(asset.url for asset in assets_by_key.values() if asset.url)
        return sorted(url for url in urls if url)

    @staticmethod
    def _web_urls(assets_by_key: dict[str, AssetDocument]) -> list[str]:
        urls = {asset.url for asset in assets_by_key.values() if asset.url}
        return sorted(url for url in urls if url)

    @classmethod
    def _get_or_create_web_asset(
        cls,
        assets_by_key: dict[str, AssetDocument],
        engagement_id: str,
        url: str,
    ) -> AssetDocument:
        key = f"url:{url.lower().rstrip('/')}"
        asset = assets_by_key.get(key)
        if asset is None:
            asset = AssetDocument(
                engagement_id=engagement_id,
                asset_type="web_app",
                url=url,
            )
            assets_by_key[key] = asset
        return asset

    @staticmethod
    def _is_forbidden_host(scope: ScopeDocument, host_or_ip: str) -> bool:
        forbidden = {h.lower() for h in scope.forbidden_spec.forbidden_hosts}
        host = host_or_ip.lower().strip()
        return host in forbidden

    @classmethod
    def _is_forbidden_url(cls, scope: ScopeDocument, url: str) -> bool:
        hostname = (urlparse(url).hostname or "").lower()
        return bool(hostname and cls._is_forbidden_host(scope, hostname))

    @classmethod
    def _is_forbidden_asset(cls, scope: ScopeDocument, asset: AssetDocument) -> bool:
        if asset.ip and cls._is_forbidden_host(scope, asset.ip):
            return True
        if asset.url and cls._is_forbidden_url(scope, asset.url):
            return True
        return False
