"""Shodan lookup tool."""

import asyncio
import logging
import os

import shodan

from src.models.asset import ServiceInfo

logger = logging.getLogger(__name__)


async def shodan_lookup(
    ip: str,
    api_key: str | None = None,
) -> dict:
    """
    Look up an IP address in Shodan.

    Args:
        ip: IP address to look up
        api_key: Shodan API key (defaults to SHODAN_API_KEY env var)

    Returns:
        Dictionary with:
        - vulns: List of CVE IDs
        - services: List of ServiceInfo objects
        - ports: List of open ports
        - hostnames: List of hostnames
        - os: Detected operating system
        - org: Organization
        - isp: ISP
    """
    api_key = api_key or os.getenv("SHODAN_API_KEY")

    if not api_key:
        logger.warning("No Shodan API key provided, skipping lookup")
        return {
            "vulns": [],
            "services": [],
            "ports": [],
            "hostnames": [],
            "os": None,
            "org": None,
            "isp": None,
        }

    logger.info(f"Looking up {ip} in Shodan")

    # Run Shodan API call in thread pool (it's synchronous)
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, _shodan_lookup_sync, ip, api_key
    )

    return result


def _shodan_lookup_sync(ip: str, api_key: str) -> dict:
    """Synchronous Shodan lookup (runs in thread pool)."""
    result = {
        "vulns": [],
        "services": [],
        "ports": [],
        "hostnames": [],
        "os": None,
        "org": None,
        "isp": None,
    }

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        # Extract vulnerabilities
        if "vulns" in host:
            result["vulns"] = list(host["vulns"])
            logger.info(f"Found {len(result['vulns'])} vulnerabilities for {ip}")

        # Extract ports
        result["ports"] = host.get("ports", [])

        # Extract hostnames
        result["hostnames"] = host.get("hostnames", [])

        # Extract OS
        result["os"] = host.get("os")

        # Extract organization info
        result["org"] = host.get("org")
        result["isp"] = host.get("isp")

        # Extract detailed service info from data array
        services: list[ServiceInfo] = []
        for item in host.get("data", []):
            port = item.get("port")
            if port:
                # Try to get service name and version
                service_name = item.get("product") or item.get("_shodan", {}).get("module", "unknown")
                version = item.get("version")

                services.append(ServiceInfo(
                    port=port,
                    service=service_name,
                    version=version,
                ))

        result["services"] = services

        logger.info(f"Shodan lookup complete for {ip}: {len(result['ports'])} ports, {len(result['vulns'])} vulns")

    except shodan.APIError as e:
        if "No information available" in str(e):
            logger.info(f"No Shodan data available for {ip}")
        else:
            logger.warning(f"Shodan API error for {ip}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in Shodan lookup: {e}")

    return result