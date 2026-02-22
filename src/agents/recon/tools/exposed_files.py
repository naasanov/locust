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
    """Check if a single file is exposed and validate content."""
    url = f"{base_url}{path}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            # Always do GET to validate content (HEAD doesn't give us content)
            response = await client.get(url)

            # Check for success status codes
            if response.status_code == 200:
                content = response.text

                # Skip if it looks like an error page or SPA fallback
                if _is_error_page(content, path):
                    return None

                # Validate content matches expected file type
                if not _validate_file_content(content, path):
                    logger.debug(f"Content validation failed for {path}")
                    return None

                size = len(response.content)
                logger.debug(f"Found exposed file: {path} ({size} bytes)")
                return ExposedFile(path=path, size=size)

            elif response.status_code == 403:
                # 403 might indicate file exists but access denied
                # But first check if it's a generic WAF/security challenge page
                content = response.text
                if _is_security_challenge(content):
                    logger.debug(f"403 appears to be WAF/security challenge for {path}")
                    return None
                # Only report if it seems like a real access denied for a specific file
                logger.debug(f"Found forbidden file (403): {path}")
                return ExposedFile(path=path, size=None)

    except httpx.TimeoutException:
        pass
    except httpx.RequestError:
        pass
    except Exception as e:
        logger.debug(f"Error checking {url}: {e}")

    return None


def _is_security_challenge(content: str) -> bool:
    """
    Detect WAF/security challenge pages that return 403 for all requests.

    These pages block bots and return 403 regardless of whether the path exists.
    """
    content_lower = content.lower()

    # Common security challenge indicators
    challenge_indicators = [
        "security checkpoint",
        "vercel security",
        "cloudflare",
        "captcha",
        "challenge-platform",
        "ddos protection",
        "access denied",
        "bot protection",
        "human verification",
        "please wait while we verify",
        "checking your browser",
        "just a moment",
        "ray id",  # Cloudflare
        "cf-ray",  # Cloudflare
        "akamai",
        "incapsula",
        "sucuri",
        "imperva",
    ]

    return any(indicator in content_lower for indicator in challenge_indicators)


def _is_error_page(content: str, expected_path: str) -> bool:
    """Check if response looks like a generic error page or SPA fallback."""
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

    # SPA detection - if this looks like HTML but we're checking for a non-HTML file
    if _is_spa_fallback(content, expected_path):
        return True

    return False


def _is_spa_fallback(content: str, expected_path: str) -> bool:
    """
    Detect SPA fallback pages that return index.html for all routes.

    SPAs often return 200 OK with HTML content for any path,
    which creates false positives for sensitive file detection.
    """
    content_lower = content.lower()

    # Files that should NOT be HTML
    non_html_extensions = [
        ".env", ".git", ".sql", ".json", ".yml", ".yaml", ".xml",
        ".php", ".py", ".rb", ".js", ".ts", ".lock", ".txt",
        ".key", ".pem", ".pub", "id_rsa", "credentials",
        ".htaccess", ".htpasswd", ".dockerignore", "Dockerfile",
        "Gemfile", "Pipfile", "Jenkinsfile", "Makefile",
    ]

    # Check if this is a file type that shouldn't be HTML
    is_non_html_file = any(
        expected_path.lower().endswith(ext) or ext in expected_path.lower()
        for ext in non_html_extensions
    )

    if not is_non_html_file:
        return False

    # Detect HTML content
    html_indicators = [
        "<!doctype html",
        "<html",
        "<head>",
        "<body>",
        "<script",
        "<link rel=",
        "<meta charset",
    ]

    is_html = any(indicator in content_lower for indicator in html_indicators)

    if is_html:
        # This is HTML but we expected a config file - likely SPA fallback
        return True

    return False


def _validate_file_content(content: str, path: str) -> bool:
    """
    Validate that the response content matches expected file type.

    Returns True if content looks legitimate for the file type.
    """
    content_stripped = content.strip()
    content_lower = content.lower()

    # .env files should have KEY=value format
    if ".env" in path:
        lines = content_stripped.split("\n")
        env_lines = [l for l in lines if "=" in l and not l.strip().startswith("#")]
        return len(env_lines) > 0

    # .git/config should have git config format
    if ".git/config" in path:
        return "[core]" in content or "[remote" in content or "[branch" in content

    # .git/HEAD should reference a branch
    if ".git/HEAD" in path:
        return content_stripped.startswith("ref: ") or len(content_stripped) == 40

    # JSON files should be valid JSON-ish
    if path.endswith(".json"):
        return content_stripped.startswith("{") or content_stripped.startswith("[")

    # YAML files should have YAML structure
    if path.endswith((".yml", ".yaml")):
        return ":" in content and not content_stripped.startswith("<")

    # SQL files should have SQL keywords
    if path.endswith(".sql"):
        sql_keywords = ["CREATE", "INSERT", "SELECT", "DROP", "ALTER", "TABLE"]
        return any(kw in content.upper() for kw in sql_keywords)

    # PHP files should have PHP tags
    if path.endswith(".php"):
        return "<?php" in content or "<?" in content

    # robots.txt should have robot directives
    if "robots.txt" in path:
        return "user-agent" in content_lower or "disallow" in content_lower or "allow" in content_lower

    # SSH keys
    if "id_rsa" in path and ".pub" not in path:
        return "-----BEGIN" in content and "PRIVATE KEY" in content

    if "id_rsa.pub" in path:
        return content_stripped.startswith("ssh-rsa ") or content_stripped.startswith("ssh-ed25519 ")

    # AWS credentials
    if "credentials" in path and "aws" in path.lower():
        return "[default]" in content or "aws_access_key_id" in content_lower

    # Default: if we can't validate specifically, it's probably fine if it's not HTML
    html_indicators = ["<!doctype", "<html", "<head>", "<body>"]
    return not any(ind in content_lower for ind in html_indicators)