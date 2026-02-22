"""HTTP endpoint crawler tool."""

import httpx


async def crawl_endpoints(
    url: str,
    max_depth: int = 2,
    timeout: float = 10.0,
) -> list[str]:
    """
    Crawl a web application to discover endpoints.

    Args:
        url: Base URL to start crawling
        max_depth: Maximum crawl depth (default: 2)
        timeout: Request timeout in seconds

    Returns:
        List of discovered endpoint paths (e.g., ["/admin", "/api/v1/users"])
    """
    # TODO: Implement in REC-02
    raise NotImplementedError("crawl_endpoints will be implemented in REC-02")
