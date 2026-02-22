"""Shodan lookup tool."""

import os

import shodan


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
        - services: List of ServiceInfo dicts
        - ports: List of open ports
    """
    # TODO: Implement in REC-02
    raise NotImplementedError("shodan_lookup will be implemented in REC-02")