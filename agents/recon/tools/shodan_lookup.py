"""Shodan lookup tool."""

import os
from typing import Optional

import shodan


def shodan_lookup(
    ip: str,
    api_key: Optional[str] = None,
) -> dict:
    """
    Look up an IP address in Shodan.

    Args:
        ip: IP address to look up
        api_key: Shodan API key (defaults to SHODAN_API_KEY env var)

    Returns:
        Dictionary with:
        - vulns: List of CVE IDs
        - services: List of service dicts
        - ports: List of open ports
    """
    # TODO: Implement in REC-02
    raise NotImplementedError("shodan_lookup will be implemented in REC-02")