from src.models.asset import AssetDocument
from src.models.scope import ScopeDocument


class ReconAgent:
    """
    Deterministic pipeline: run_nmap → enumerate_subdomains → crawl_endpoints
    → check_exposed_files → shodan_lookup, then single Gemini Flash call to score.

    Implement run() and replace this stub.
    """

    async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
        raise NotImplementedError
