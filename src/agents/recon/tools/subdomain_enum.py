"""Subdomain enumeration tool."""

import asyncio
import logging
import socket

import httpx

from src.models.asset import AssetDocument

logger = logging.getLogger(__name__)

# Common subdomains to brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging", "test",
    "api", "admin", "portal", "shop", "store", "app", "mobile", "m", "cdn",
    "static", "assets", "media", "img", "images", "video", "vpn", "remote",
    "gateway", "gw", "router", "firewall", "proxy", "mail2", "webdisk", "cpanel",
    "whm", "autodiscover", "autoconfig", "imap", "pop3", "secure", "ssl",
    "beta", "demo", "dashboard", "auth", "login", "sso", "id", "account",
    "accounts", "my", "support", "help", "docs", "wiki", "git", "gitlab",
    "github", "jenkins", "ci", "build", "deploy", "monitor", "grafana",
    "prometheus", "kibana", "elastic", "logs", "status", "health", "internal",
    "intranet", "extranet", "private", "public", "web", "www2", "www3",
    "old", "new", "v1", "v2", "legacy", "backup", "bak", "temp", "tmp",
]


async def enumerate_subdomains(
    domain: str,
    engagement_id: str,
) -> list[AssetDocument]:
    """
    Enumerate subdomains for a given domain.

    Uses multiple techniques:
    - Certificate transparency logs (crt.sh)
    - DNS brute forcing with common wordlist

    Args:
        domain: Base domain to enumerate (e.g., "example.com")
        engagement_id: Parent engagement ID

    Returns:
        List of AssetDocuments with asset_type="subdomain"
    """
    logger.info(f"Starting subdomain enumeration for {domain}")

    # Collect subdomains from multiple sources
    subdomains: set[str] = set()

    # Source 1: Certificate transparency logs
    ct_subs = await _fetch_crt_sh(domain)
    subdomains.update(ct_subs)
    logger.info(f"Found {len(ct_subs)} subdomains from crt.sh")

    # Source 2: DNS brute forcing
    brute_subs = await _brute_force_subdomains(domain)
    subdomains.update(brute_subs)
    logger.info(f"Found {len(brute_subs)} subdomains from brute force")

    # Resolve IPs and create assets
    assets: list[AssetDocument] = []

    for subdomain in sorted(subdomains):
        ip = await _resolve_dns(subdomain)

        asset = AssetDocument(
            engagement_id=engagement_id,
            asset_type="subdomain",
            url=f"https://{subdomain}",
            ip=ip,
        )
        assets.append(asset)

    logger.info(f"Enumeration complete: {len(assets)} subdomains for {domain}")
    return assets


async def _fetch_crt_sh(domain: str) -> set[str]:
    """Fetch subdomains from certificate transparency logs via crt.sh."""
    subdomains: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json"
            )

            if response.status_code != 200:
                logger.warning(f"crt.sh returned status {response.status_code}")
                return subdomains

            data = response.json()

            for entry in data:
                name = entry.get("name_value", "")
                # Handle wildcard and multi-line entries
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.startswith("*."):
                        line = line[2:]
                    if line.endswith(domain) and line != domain:
                        subdomains.add(line)

    except httpx.TimeoutException:
        logger.warning("crt.sh request timed out")
    except Exception as e:
        logger.warning(f"crt.sh lookup failed: {e}")

    return subdomains


async def _brute_force_subdomains(domain: str) -> set[str]:
    """Brute force common subdomains via DNS resolution."""
    found: set[str] = set()

    # Create tasks for parallel DNS resolution
    tasks = []
    for prefix in COMMON_SUBDOMAINS:
        subdomain = f"{prefix}.{domain}"
        tasks.append(_check_subdomain(subdomain))

    # Run with concurrency limit
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for subdomain, exists in zip(
        [f"{p}.{domain}" for p in COMMON_SUBDOMAINS],
        results
    ):
        if exists is True:
            found.add(subdomain)

    return found


async def _check_subdomain(subdomain: str) -> bool:
    """Check if a subdomain exists via DNS."""
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        return True
    except socket.gaierror:
        return False


async def _resolve_dns(hostname: str) -> str | None:
    """Resolve hostname to IP address."""
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
        return ip
    except socket.gaierror:
        return None