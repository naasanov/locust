"""Backward-compatible wrapper for Censys enrichment."""

from .censys_lookup import censys_lookup


async def shodan_lookup(ip: str, api_key: str | None = None) -> dict:
    """
    Compatibility alias.

    Existing callers can continue importing `shodan_lookup`, but enrichment now
    comes from Censys.
    """
    return await censys_lookup(ip=ip, api_key=api_key)
