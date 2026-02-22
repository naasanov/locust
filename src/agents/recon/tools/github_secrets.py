"""GitHub secret scanning tool."""

import asyncio
import logging
import os
import re
from urllib.parse import urlparse

import httpx

from src.models.asset import SecretFound

logger = logging.getLogger(__name__)

# Common secret patterns to search for
SECRET_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "aws_secret_access_key"),
    # GitHub tokens
    (r"ghp_[A-Za-z0-9]{36}", "github_personal_access_token"),
    (r"gho_[A-Za-z0-9]{36}", "github_oauth_token"),
    (r"ghu_[A-Za-z0-9]{36}", "github_user_token"),
    (r"ghs_[A-Za-z0-9]{36}", "github_server_token"),
    (r"ghr_[A-Za-z0-9]{36}", "github_refresh_token"),
    # Slack
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "slack_token"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24}", "stripe_secret_key"),
    (r"rk_live_[0-9a-zA-Z]{24}", "stripe_restricted_key"),
    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
    # Generic API keys
    (r"(?i)api[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{32,})", "generic_api_key"),
    (r"(?i)api[_\-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{32,})", "generic_api_secret"),
    # Database connection strings
    (r"(?i)(?:mysql|postgresql|postgres|mongodb)://[^\s'\"]+", "database_url"),
    # Private keys
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
    # JWT secrets
    (r"(?i)jwt[_\-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{32,})", "jwt_secret"),
]


async def scan_github_secrets(
    domain: str,
    github_token: str | None = None,
    max_results: int = 10,
) -> list[SecretFound]:
    """
    Search GitHub for exposed secrets related to a domain.

    Uses GitHub code search to find potential secrets in public repositories.

    Args:
        domain: Domain to search for (e.g., "acmecorp.com")
        github_token: GitHub personal access token for API access
        max_results: Maximum number of results to process

    Returns:
        List of SecretFound objects for discovered secrets
    """
    logger.info(f"Scanning GitHub for secrets related to {domain}")

    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("No GitHub token provided, skipping GitHub secret scan")
        return []

    secrets: list[SecretFound] = []

    # Extract org name from domain
    org_name = _extract_org_name(domain)

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Search for code containing the domain
            search_queries = [
                f'"{domain}" filename:.env',
                f'"{domain}" filename:config',
                f'"{org_name}" filename:.env',
                f'"{org_name}" password OR secret OR api_key',
            ]

            for query in search_queries:
                try:
                    response = await client.get(
                        "https://api.github.com/search/code",
                        headers=headers,
                        params={"q": query, "per_page": max_results},
                    )

                    if response.status_code == 403:
                        logger.warning("GitHub API rate limit exceeded")
                        break

                    if response.status_code != 200:
                        logger.warning(f"GitHub search failed: {response.status_code}")
                        continue

                    data = response.json()
                    items = data.get("items", [])

                    for item in items[:max_results]:
                        repo_name = item.get("repository", {}).get("full_name", "")
                        file_path = item.get("path", "")
                        html_url = item.get("html_url", "")

                        # Fetch file content to scan for secrets
                        file_url = item.get("url")
                        if file_url:
                            found = await _scan_file_for_secrets(
                                client, headers, file_url, repo_name, file_path
                            )
                            secrets.extend(found)

                except Exception as e:
                    logger.warning(f"Error in GitHub search: {e}")

                # Rate limit protection
                await asyncio.sleep(1)

    except Exception as e:
        logger.error(f"GitHub secret scan failed: {e}")

    # Deduplicate by value
    seen_values: set[str] = set()
    unique_secrets: list[SecretFound] = []
    for secret in secrets:
        if secret.value not in seen_values:
            seen_values.add(secret.value)
            unique_secrets.append(secret)

    logger.info(f"Found {len(unique_secrets)} unique secrets for {domain}")
    return unique_secrets


async def _scan_file_for_secrets(
    client: httpx.AsyncClient,
    headers: dict,
    file_url: str,
    repo_name: str,
    file_path: str,
) -> list[SecretFound]:
    """Scan a GitHub file for secrets."""
    secrets: list[SecretFound] = []

    try:
        response = await client.get(file_url, headers=headers)
        if response.status_code != 200:
            return []

        data = response.json()
        content = data.get("content", "")

        # Decode base64 content
        import base64
        try:
            decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        except Exception:
            return []

        # Search for secret patterns
        for pattern, secret_type in SECRET_PATTERNS:
            matches = re.findall(pattern, decoded)
            for match in matches:
                # Get the actual secret value
                value = match if isinstance(match, str) else match[0] if match else ""
                if value and len(value) >= 8:  # Minimum length filter
                    # Redact the middle portion
                    redacted = _redact_secret(value)

                    secrets.append(SecretFound(
                        source="github",
                        type=secret_type,
                        value=redacted,
                        repo=repo_name,
                        commit=None,  # Would need additional API call
                    ))

    except Exception as e:
        logger.debug(f"Error scanning file {file_path}: {e}")

    return secrets


def _extract_org_name(domain: str) -> str:
    """Extract organization name from domain."""
    # Remove common TLDs and subdomains
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return parts[-2]  # e.g., "acmecorp" from "acmecorp.com"
    return domain


def _redact_secret(value: str) -> str:
    """Redact the middle portion of a secret for safe logging."""
    if len(value) <= 8:
        return value[:2] + "..." + value[-2:]
    return value[:4] + "...REDACTED..." + value[-4:]
