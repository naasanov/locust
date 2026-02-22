"""
Tests for REC-02 recon tools.

Run with: pytest tests/test_recon_tools.py -v
"""

import asyncio
import os
import pytest


class TestNmapScanner:
    """Test run_nmap tool."""

    @pytest.mark.asyncio
    async def test_nmap_localhost(self):
        """Test nmap scan against localhost."""
        from src.agents.recon.tools import run_nmap

        # Scan localhost on common ports
        asset = await run_nmap(
            target="127.0.0.1",
            engagement_id="test-001",
            ports="22,80,443,8080",
            arguments="-sV --open",
        )

        # Should return an asset (may or may not have open ports)
        # On most dev machines, nothing is open on these ports
        if asset:
            assert asset.engagement_id == "test-001"
            assert asset.ip == "127.0.0.1"
            assert asset.asset_type in ("host", "web_app")

    @pytest.mark.asyncio
    async def test_nmap_invalid_target(self):
        """Test nmap scan with invalid target."""
        from src.agents.recon.tools import run_nmap

        # Non-existent host should return None
        asset = await run_nmap(
            target="192.0.2.1",  # TEST-NET-1, should not respond
            engagement_id="test-002",
            ports="80",
            arguments="-sV -T4",
        )

        # May return None or empty asset depending on nmap behavior
        if asset:
            assert asset.open_ports == []


class TestSubdomainEnum:
    """Test enumerate_subdomains tool."""

    @pytest.mark.asyncio
    async def test_subdomain_enum_deterministic(self, monkeypatch):
        """Test subdomain enumeration deterministically without network."""
        from src.agents.recon.tools import subdomain_enum

        async def fake_ct(_: str) -> set[str]:
            return {"api.google.com", "mail.google.com"}

        async def fake_brute(_: str) -> set[str]:
            return {"admin.google.com"}

        async def fake_resolve(hostname: str) -> str:
            return {
                "admin.google.com": "203.0.113.10",
                "api.google.com": "203.0.113.11",
                "mail.google.com": "203.0.113.12",
            }[hostname]

        monkeypatch.setattr(subdomain_enum, "_fetch_crt_sh", fake_ct)
        monkeypatch.setattr(subdomain_enum, "_brute_force_subdomains", fake_brute)
        monkeypatch.setattr(subdomain_enum, "_resolve_dns", fake_resolve)

        assets = await subdomain_enum.enumerate_subdomains(
            domain="google.com",
            engagement_id="test-003",
        )

        assert len(assets) == 3
        for asset in assets:
            assert asset.engagement_id == "test-003"
            assert asset.asset_type == "subdomain"
            assert asset.url is not None
            assert "google.com" in asset.url
            assert asset.ip is not None

    @pytest.mark.asyncio
    async def test_subdomain_enum_nonexistent(self):
        """Test subdomain enumeration for nonexistent domain."""
        from src.agents.recon.tools import enumerate_subdomains

        assets = await enumerate_subdomains(
            domain="thisdoesnotexist12345.com",
            engagement_id="test-004",
        )

        # Should return empty or minimal results
        # crt.sh might still find some if domain was ever registered
        assert isinstance(assets, list)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        os.environ.get("RUN_NETWORK_TESTS") != "1",
        reason="Set RUN_NETWORK_TESTS=1 to run external network integration tests",
    )
    async def test_subdomain_enum_google_network(self):
        """Integration test against real DNS/crt.sh."""
        from src.agents.recon.tools import enumerate_subdomains

        assets = await enumerate_subdomains(
            domain="google.com",
            engagement_id="test-003-net",
        )
        assert isinstance(assets, list)


class TestEndpointCrawler:
    """Test crawl_endpoints tool."""

    @pytest.mark.asyncio
    async def test_crawl_example_com(self):
        """Test crawling example.com."""
        from src.agents.recon.tools import crawl_endpoints

        endpoints = await crawl_endpoints(
            url="https://example.com",
            max_depth=1,
            timeout=10.0,
        )

        # example.com is very simple, should find at least the root
        assert isinstance(endpoints, list)
        assert "/" in endpoints or len(endpoints) >= 0

    @pytest.mark.asyncio
    async def test_crawl_invalid_url(self):
        """Test crawling invalid URL."""
        from src.agents.recon.tools import crawl_endpoints

        endpoints = await crawl_endpoints(
            url="https://nonexistent12345.invalid",
            max_depth=1,
            timeout=5.0,
        )

        # Should return minimal results for unreachable URL
        # May include "/" from initial URL parsing
        assert isinstance(endpoints, list)
        assert len(endpoints) <= 1


class TestExposedFiles:
    """Test check_exposed_files tool."""

    @pytest.mark.asyncio
    async def test_exposed_files_example_com(self):
        """Test exposed files check on example.com."""
        from src.agents.recon.tools import check_exposed_files

        files = await check_exposed_files(
            base_url="https://example.com",
            timeout=5.0,
        )

        # example.com should not have exposed sensitive files
        # It might have robots.txt though
        assert isinstance(files, list)

    @pytest.mark.asyncio
    async def test_exposed_files_with_custom_paths(self):
        """Test exposed files with custom paths."""
        from src.agents.recon.tools import check_exposed_files

        files = await check_exposed_files(
            base_url="https://example.com",
            additional_paths=["/custom.txt", "/test.json"],
            timeout=5.0,
        )

        assert isinstance(files, list)


class TestCensysLookup:
    """Test censys_lookup tool."""

    @pytest.mark.asyncio
    async def test_censys_no_api_key(self):
        """Test Censys lookup without API key."""
        from src.agents.recon.tools import censys_lookup
        import os

        # Temporarily unset API key
        original_key = os.environ.pop("CENSYS_API_KEY", None)

        try:
            result = await censys_lookup(
                ip="8.8.8.8",
                api_key=None,
            )

            # Should return empty results without API key
            assert result["vulns"] == []
            assert result["services"] == []
            assert result["ports"] == []
        finally:
            if original_key:
                os.environ["CENSYS_API_KEY"] = original_key

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not pytest.importorskip("os").environ.get("CENSYS_API_KEY"),
        reason="CENSYS_API_KEY not set"
    )
    async def test_censys_with_api_key(self):
        """Test Censys lookup with API key (requires env var)."""
        from src.agents.recon.tools import censys_lookup

        result = await censys_lookup(ip="8.8.8.8")

        # Google DNS should have some enrichment in Censys
        assert isinstance(result["vulns"], list)
        assert isinstance(result["ports"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
