"""Main Recon Agent implementation."""

import hashlib
import json
import logging
from typing import Optional

from .models.asset import Asset
from .models.scope import Scope
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

    def __init__(
        self,
        db_client,  # pymongo.MongoClient
        gemini_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
    ):
        """
        Initialize the Recon Agent.

        Args:
            db_client: MongoDB client instance
            gemini_api_key: API key for Gemini Flash scoring
            shodan_api_key: API key for Shodan lookups
        """
        self.db = db_client
        self.scorer = GeminiScorer(api_key=gemini_api_key)
        self.shodan_api_key = shodan_api_key

    def verify_scope_integrity(self, scope_doc: dict, on_chain_hash: str) -> bool:
        """
        Verify scope document against on-chain hash.

        Args:
            scope_doc: Scope document from MongoDB
            on_chain_hash: SHA-256 hash from Solana engagement account

        Returns:
            True if hashes match, False otherwise
        """
        # Compute hash of the MongoDB document
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

    def run_cycle(self, scope: Scope) -> list[Asset]:
        """
        Run a complete recon cycle.

        All five tools run deterministically in order.
        Gemini scores at the end.

        Args:
            scope: Verified scope document

        Returns:
            List of scored assets
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("run_cycle will be implemented in REC-03")

    def persist_assets(self, assets: list[Asset]) -> int:
        """
        Save discovered assets to MongoDB.

        Args:
            assets: List of assets to persist

        Returns:
            Number of assets upserted
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("persist_assets will be implemented in REC-03")