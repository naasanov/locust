"""
Full integration test for the Recon System.

Tests the complete recon pipeline:
1. nmap scanning
2. subdomain enumeration
3. endpoint crawling
4. exposed files detection
5. Censys lookup
6. gemini scoring

Run with: pytest tests/test_full_recon.py -v -s
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
import pytest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def run_full_recon_test(target_domain: str = "example.com", target_ip: str | None = None):
    """
    Run a full recon test against a target.

    Args:
        target_domain: Domain to scan (default: example.com for safe testing)
        target_ip: Optional IP to scan with nmap/Censys
    """
    from src.config import get_settings
    from src.agents.recon import ReconAgent
    from src.models.scope import (
        ScopeDocument, Targets, ForbiddenSpec,
        EngagementConstraints, ActiveHours, ActiveWindow
    )

    settings = get_settings()

    print("\n" + "=" * 60)
    print("FULL RECON SYSTEM TEST")
    print("=" * 60)
    print(f"Target Domain: {target_domain if target_domain != 'none' else 'None'}")
    print(f"Target IP: {target_ip or 'None (will use domain resolution)'}")
    print(f"Gemini API Key: {'Set' if settings.GEMINI_API_KEY else 'NOT SET'}")
    print(f"Censys API Key: {'Set' if settings.CENSYS_API_KEY else 'NOT SET'}")
    print(f"GitHub Token: {'Set' if getattr(settings, 'GITHUB_TOKEN', None) else 'NOT SET'}")
    print("=" * 60 + "\n")

    # Create test scope document
    # If IP is provided without domain, don't include a domain
    domains = [target_domain] if target_domain and target_domain != "none" else []

    scope = ScopeDocument(
        engagement_id="test-full-recon-001",
        customer="Test Customer",
        targets=Targets(
            domains=domains,
            ip_ranges=[target_ip] if target_ip else [],
        ),
        forbidden_spec=ForbiddenSpec(
            forbidden_hosts=[],
            forbidden_actions=["destructive_payloads", "dos_testing"],
        ),
        constraints=EngagementConstraints(
            active_hours=ActiveHours(
                timezone="UTC",
                windows=[ActiveWindow(days=["mon", "tue", "wed", "thu", "fri", "sat", "sun"], start="00:00", end="23:59")],
            ),
            expires_at=datetime(2026, 12, 31, tzinfo=timezone.utc),
        ),
    )

    # Initialize ReconAgent (without DB persistence for testing)
    agent = ReconAgent(
        gemini_api_key=settings.GEMINI_API_KEY,
        censys_api_key=settings.CENSYS_API_KEY,
        github_token=getattr(settings, 'GITHUB_TOKEN', None),
        persist_assets=False,  # Don't write to DB for testing
    )

    print("Starting recon cycle...")
    print("-" * 40)

    try:
        assets = await agent.run(scope)

        print("\n" + "=" * 60)
        print(f"RECON COMPLETE - Found {len(assets)} assets")
        print("=" * 60 + "\n")

        for i, asset in enumerate(assets, 1):
            print(f"\n--- Asset {i} ---")
            print(f"  Type: {asset.asset_type}")
            print(f"  IP: {asset.ip}")
            print(f"  URL: {asset.url}")
            print(f"  Open Ports: {asset.open_ports}")
            print(f"  Services: {[f'{s.service}:{s.port}' for s in asset.services]}")
            print(f"  Tech Stack: {asset.tech_stack}")
            print(f"  Endpoints: {asset.endpoints[:5]}{'...' if len(asset.endpoints) > 5 else ''}")
            print(f"  Exposed Files: {[f.path for f in asset.exposed_files]}")
            print(f"  Censys Vulns: {asset.shodan_vulns}")
            print(f"  Secrets Found: {[f'{s.type} ({s.source})' for s in asset.secrets_found]}")
            print(f"  Cloud Issues: {[f'{c.type}: {c.resource}' for c in asset.cloud_issues]}")
            print(f"  Attack Surface Score: {asset.attack_surface_score:.2f}")
            print(f"  Score Reasoning: {asset.score_reasoning}")

        # Print highest scoring asset as JSON in canonical AssetDocument schema format
        if assets:
            import json
            print("\n" + "=" * 60)
            print("ASSETDOCUMENT OUTPUT FORMAT (highest-score asset)")
            print("=" * 60)
            best_asset = max(assets, key=lambda a: a.attack_surface_score)
            asset_dict = best_asset.to_recon_output()
            print(json.dumps(asset_dict, indent=2, default=str))

        print("\n" + "=" * 60)
        print("TEST PASSED")
        print("=" * 60)

        return assets

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        raise


@pytest.mark.asyncio
async def test_individual_tools():
    """Test each tool individually."""
    from src.config import get_settings
    from src.agents.recon.tools import (
        run_nmap,
        enumerate_subdomains,
        crawl_endpoints,
        check_exposed_files,
        censys_lookup,
    )

    settings = get_settings()

    print("\n" + "=" * 60)
    print("INDIVIDUAL TOOL TESTS")
    print("=" * 60 + "\n")

    # Test 1: Endpoint Crawler
    print("\n[1/5] Testing endpoint crawler against example.com...")
    try:
        endpoints = await crawl_endpoints(url="https://example.com", max_depth=1)
        print(f"  Found {len(endpoints)} endpoints: {endpoints}")
        print("  ✓ Endpoint crawler working")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Test 2: Exposed Files
    print("\n[2/5] Testing exposed files checker...")
    try:
        files = await check_exposed_files(base_url="https://example.com")
        print(f"  Found {len(files)} exposed files: {[f.path for f in files]}")
        print("  ✓ Exposed files checker working")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Test 3: Subdomain Enumeration (limited to avoid long wait)
    print("\n[3/5] Testing subdomain enumeration (crt.sh only)...")
    try:
        assets = await enumerate_subdomains(domain="example.com", engagement_id="test-001")
        print(f"  Found {len(assets)} subdomains")
        for a in assets[:3]:
            print(f"    - {a.url} ({a.ip})")
        if len(assets) > 3:
            print(f"    ... and {len(assets) - 3} more")
        print("  ✓ Subdomain enumeration working")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    # Test 4: Censys Lookup
    print("\n[4/5] Testing Censys lookup...")
    if settings.CENSYS_API_KEY:
        try:
            # Use Google DNS as safe test target
            result = await censys_lookup(ip="8.8.8.8", api_key=settings.CENSYS_API_KEY)
            print(f"  Ports: {result['ports']}")
            print(f"  Vulns: {result['vulns']}")
            print(f"  Org: {result['org']}")
            print("  ✓ Censys lookup working")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    else:
        print("  ⚠ Skipped (CENSYS_API_KEY not set)")

    # Test 5: Nmap (localhost only for safety)
    print("\n[5/5] Testing nmap scanner (localhost)...")
    try:
        asset = await run_nmap(target="127.0.0.1", engagement_id="test-001", ports="22,80,443,8080")
        if asset:
            print(f"  IP: {asset.ip}")
            print(f"  Open Ports: {asset.open_ports}")
            print(f"  Services: {[f'{s.service}:{s.port}' for s in asset.services]}")
        else:
            print("  No open ports found on localhost")
        print("  ✓ Nmap scanner working")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    print("\n" + "=" * 60)
    print("INDIVIDUAL TOOL TESTS COMPLETE")
    print("=" * 60)


@pytest.mark.asyncio
async def test_gemini_scoring():
    """Test the Gemini scoring component."""
    from src.config import get_settings
    from src.agents.recon.scoring import GeminiScorer
    from src.models.asset import AssetDocument, ServiceInfo, ExposedFile

    settings = get_settings()

    print("\n" + "=" * 60)
    print("GEMINI SCORING TEST")
    print("=" * 60 + "\n")

    if not settings.GEMINI_API_KEY:
        print("⚠ GEMINI_API_KEY not set, skipping scoring test")
        return

    # Create test assets with varying risk profiles
    test_assets = [
        AssetDocument(
            engagement_id="test-001",
            asset_type="web_app",
            url="https://secure-example.com",
            open_ports=[443],
            services=[ServiceInfo(port=443, service="https", version="TLS 1.3")],
            endpoints=["/"],
        ),
        AssetDocument(
            engagement_id="test-001",
            asset_type="host",
            ip="192.168.1.1",
            open_ports=[22, 80, 443, 3306, 5432],
            services=[
                ServiceInfo(port=22, service="ssh", version="OpenSSH 8.2"),
                ServiceInfo(port=80, service="http", version="nginx 1.18"),
                ServiceInfo(port=3306, service="mysql", version="MySQL 5.7"),
                ServiceInfo(port=5432, service="postgresql", version="12.4"),
            ],
            exposed_files=[
                ExposedFile(path="/.env", size=1024),
                ExposedFile(path="/.git/config", size=256),
            ],
            shodan_vulns=["CVE-2021-44228", "CVE-2020-1234"],
        ),
    ]

    try:
        scorer = GeminiScorer(api_key=settings.GEMINI_API_KEY)
        scored = await scorer.score_assets(test_assets)

        print("Scoring Results:")
        print("-" * 40)
        for asset in scored:
            print(f"\nAsset: {asset.url or asset.ip}")
            print(f"  Score: {asset.attack_surface_score:.2f}")
            print(f"  Reasoning: {asset.score_reasoning}")

        print("\n✓ Gemini scoring working")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test the full recon system")
    parser.add_argument("--domain", default="example.com", help="Target domain")
    parser.add_argument("--ip", default=None, help="Target IP address")
    parser.add_argument("--tools-only", action="store_true", help="Only test individual tools")
    parser.add_argument("--scoring-only", action="store_true", help="Only test Gemini scoring")
    args = parser.parse_args()

    if args.tools_only:
        asyncio.run(test_individual_tools())
    elif args.scoring_only:
        asyncio.run(test_gemini_scoring())
    else:
        # Run all tests
        asyncio.run(test_individual_tools())
        asyncio.run(test_gemini_scoring())
        asyncio.run(run_full_recon_test(target_domain=args.domain, target_ip=args.ip))
