"""Exposed files checker tool."""

import asyncio
import logging

import httpx

from src.models.asset import ExposedFile

logger = logging.getLogger(__name__)

# Common sensitive files to check
SENSITIVE_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/settings.py",
    "/settings.json",
    "/database.yml",
    "/secrets.yml",
    "/secrets.json",
    "/credentials.json",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/.DS_Store",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/elmah.axd",
    "/web.config",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/composer.json",
    "/composer.lock",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/.dockerignore",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.travis.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/id_rsa",
    "/id_rsa.pub",
    "/.ssh/id_rsa",
    "/aws/credentials",
    "/.aws/credentials",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/graphql",
    "/.graphqlconfig",
]


async def check_exposed_files(
    base_url: str,
    additional_paths: list[str] | None = None,
    timeout: float = 5.0,
    concurrency: int = 10,
) -> list[ExposedFile]:
    """
    Check for exposed sensitive files on a web server.

    Args:
        base_url: Base URL to check (e.g., "https://example.com")
        additional_paths: Extra paths to check beyond the default list
        timeout: Request timeout in seconds
        concurrency: Number of concurrent requests

    Returns:
        List of ExposedFile objects for files that exist
    """
    logger.info(f"Checking exposed files on {base_url}")

    # Normalize base URL
    base_url = base_url.rstrip("/")

    # Combine default and additional paths
    paths_to_check = list(SENSITIVE_FILES)
    if additional_paths:
        paths_to_check.extend(additional_paths)

    # Remove duplicates while preserving order
    paths_to_check = list(dict.fromkeys(paths_to_check))

    exposed: list[ExposedFile] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def check_path(path: str) -> ExposedFile | None:
        async with semaphore:
            return await _check_single_file(base_url, path, timeout)

    # Check all paths concurrently
    tasks = [check_path(path) for path in paths_to_check]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, ExposedFile):
            exposed.append(result)

    logger.info(f"Found {len(exposed)} exposed files")
    return exposed


async def _check_single_file(
    base_url: str,
    path: str,
    timeout: float,
) -> ExposedFile | None:
    """Check if a single file is exposed."""
    url = f"{base_url}{path}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            response = await client.head(url)

            # Check for success status codes
            if response.status_code in (200, 403):
                # 403 might indicate file exists but access denied
                # Still worth reporting

                size = None
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        size = int(content_length)
                    except ValueError:
                        pass

                # For 200, verify it's not a generic error page
                if response.status_code == 200:
                    # Do a GET to check content
                    get_response = await client.get(url)

                    # Skip if it looks like an error page
                    if _is_error_page(get_response.text, path):
                        return None

                    size = len(get_response.content)

                logger.debug(f"Found exposed file: {path}")
                return ExposedFile(path=path, size=size)

    except httpx.TimeoutException:
        pass
    except httpx.RequestError:
        pass
    except Exception as e:
        logger.debug(f"Error checking {url}: {e}")

    return None


def _is_error_page(content: str, expected_path: str) -> bool:
    """Check if response looks like a generic error page."""
    content_lower = content.lower()

    # Common error page indicators
    error_indicators = [
        "404 not found",
        "page not found",
        "file not found",
        "not found",
        "error 404",
        "the page you requested",
        "does not exist",
        "could not be found",
    ]

    for indicator in error_indicators:
        if indicator in content_lower:
            # But make sure the path isn't in the content (could be legit)
            if expected_path.lower() not in content_lower:
                return True

    # If content is very short and doesn't look like the file type
    if len(content) < 100:
        # Short responses are usually error messages unless they're config files
        if not any(
            expected_path.endswith(ext)
            for ext in [".txt", ".json", ".yml", ".yaml", ".xml"]
        ):
            return True

    return False