"""HTTP endpoint crawler tool."""

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# Regex patterns to extract URLs from HTML
LINK_PATTERNS = [
    re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'data-url=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'url\(["\']?([^"\')\s]+)["\']?\)', re.IGNORECASE),
]

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar",
}


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
    logger.info(f"Starting crawl of {url} with max_depth={max_depth}")

    base_parsed = urlparse(url)
    base_domain = base_parsed.netloc
    base_url = f"{base_parsed.scheme}://{base_parsed.netloc}"

    visited: set[str] = set()
    endpoints: set[str] = set()
    to_visit: list[tuple[str, int]] = [(url, 0)]

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # Allow self-signed certs for testing
    ) as client:
        while to_visit:
            current_url, depth = to_visit.pop(0)

            # Normalize URL
            current_url = _normalize_url(current_url)

            if current_url in visited:
                continue

            if depth > max_depth:
                continue

            visited.add(current_url)

            # Extract path for endpoints list
            parsed = urlparse(current_url)
            if parsed.netloc == base_domain:
                path = parsed.path or "/"
                if not _should_skip(path):
                    endpoints.add(path)

            # Fetch and parse page
            try:
                response = await client.get(current_url)

                if response.status_code != 200:
                    continue

                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                html = response.text

                # Extract links
                links = _extract_links(html, base_url)

                for link in links:
                    link_parsed = urlparse(link)

                    # Only follow same-domain links
                    if link_parsed.netloc and link_parsed.netloc != base_domain:
                        continue

                    # Resolve relative URLs
                    full_url = urljoin(current_url, link)
                    full_url = _normalize_url(full_url)

                    if full_url not in visited:
                        to_visit.append((full_url, depth + 1))

            except httpx.TimeoutException:
                logger.debug(f"Timeout fetching {current_url}")
            except httpx.RequestError as e:
                logger.debug(f"Error fetching {current_url}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error crawling {current_url}: {e}")

    # Sort endpoints for consistent output
    result = sorted(endpoints)
    logger.info(f"Crawl complete: found {len(result)} endpoints")
    return result


def _extract_links(html: str, base_url: str) -> set[str]:
    """Extract all links from HTML content."""
    links: set[str] = set()

    for pattern in LINK_PATTERNS:
        matches = pattern.findall(html)
        for match in matches:
            # Skip javascript: and data: URLs
            if match.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
                continue

            # Resolve relative URLs
            full_url = urljoin(base_url, match)
            links.add(full_url)

    return links


def _normalize_url(url: str) -> str:
    """Normalize URL by removing fragments and trailing slashes."""
    parsed = urlparse(url)
    # Remove fragment
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    # Remove trailing slash except for root
    if normalized.endswith("/") and not normalized.endswith("://"):
        if len(parsed.path) > 1:
            normalized = normalized.rstrip("/")
    return normalized


def _should_skip(path: str) -> bool:
    """Check if path should be skipped (static assets, etc.)."""
    path_lower = path.lower()

    # Skip static assets
    for ext in SKIP_EXTENSIONS:
        if path_lower.endswith(ext):
            return True

    return False
