"""Exposed files checker tool."""

import httpx

from src.models.asset import ExposedFile


# Common sensitive files to check
SENSITIVE_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/settings.py",
    "/database.yml",
    "/secrets.yml",
    "/credentials.json",
    "/backup.sql",
    "/dump.sql",
    "/.DS_Store",
    "/phpinfo.php",
    "/server-status",
    "/elmah.axd",
    "/web.config",
    "/.svn/entries",
    "/.hg/hgrc",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]


async def check_exposed_files(
    base_url: str,
    additional_paths: list[str] | None = None,
    timeout: float = 5.0,
) -> list[ExposedFile]:
    """
    Check for exposed sensitive files on a web server.

    Args:
        base_url: Base URL to check (e.g., "https://example.com")
        additional_paths: Extra paths to check beyond the default list
        timeout: Request timeout in seconds

    Returns:
        List of ExposedFile objects for files that exist
    """
    # TODO: Implement in REC-02
    raise NotImplementedError("check_exposed_files will be implemented in REC-02")
