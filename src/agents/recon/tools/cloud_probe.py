"""Cloud resource probing tool (S3 buckets, Azure blobs, GCS buckets)."""

import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx

from src.models.asset import CloudIssue

logger = logging.getLogger(__name__)

# Common S3 bucket name patterns based on organization/domain
BUCKET_PATTERNS = [
    "{org}",
    "{org}-dev",
    "{org}-prod",
    "{org}-staging",
    "{org}-test",
    "{org}-backup",
    "{org}-backups",
    "{org}-assets",
    "{org}-static",
    "{org}-media",
    "{org}-uploads",
    "{org}-files",
    "{org}-data",
    "{org}-logs",
    "{org}-public",
    "{org}-private",
    "{org}-internal",
    "{org}-cdn",
    "{org}-images",
    "{org}-docs",
    "{org}-documents",
    "{org}-archive",
    "{org}-config",
    "{org}-secrets",
    "{domain}",
    "www.{domain}",
    "assets.{domain}",
    "static.{domain}",
    "media.{domain}",
    "uploads.{domain}",
    "cdn.{domain}",
]


async def probe_cloud_resources(
    domain: str,
    check_s3: bool = True,
    check_azure: bool = True,
    check_gcs: bool = True,
    timeout: float = 5.0,
    concurrency: int = 10,
) -> list[CloudIssue]:
    """
    Probe for misconfigured cloud storage resources.

    Checks for:
    - Public S3 buckets
    - Public Azure Blob Storage
    - Public Google Cloud Storage buckets

    Args:
        domain: Domain to derive bucket names from
        check_s3: Check AWS S3 buckets
        check_azure: Check Azure Blob Storage
        check_gcs: Check Google Cloud Storage
        timeout: Request timeout in seconds
        concurrency: Number of concurrent requests

    Returns:
        List of CloudIssue objects for public resources
    """
    logger.info(f"Probing cloud resources for {domain}")

    org_name = _extract_org_name(domain)
    issues: list[CloudIssue] = []
    semaphore = asyncio.Semaphore(concurrency)

    # Generate bucket names to check
    bucket_names = _generate_bucket_names(org_name, domain)

    async def check_bucket(name: str) -> list[CloudIssue]:
        async with semaphore:
            found = []
            if check_s3:
                s3_issue = await _check_s3_bucket(name, timeout)
                if s3_issue:
                    found.append(s3_issue)
            if check_azure:
                azure_issue = await _check_azure_blob(name, timeout)
                if azure_issue:
                    found.append(azure_issue)
            if check_gcs:
                gcs_issue = await _check_gcs_bucket(name, timeout)
                if gcs_issue:
                    found.append(gcs_issue)
            return found

    # Check all bucket names concurrently
    tasks = [check_bucket(name) for name in bucket_names]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            issues.extend(result)

    logger.info(f"Found {len(issues)} public cloud resources for {domain}")
    return issues


async def _check_s3_bucket(bucket_name: str, timeout: float) -> CloudIssue | None:
    """Check if an S3 bucket is public."""
    # S3 bucket URL formats
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(url)

                # Check for public access
                if response.status_code == 200:
                    # Check if it's listing contents (XML with ListBucketResult)
                    if "ListBucketResult" in response.text or "<Contents>" in response.text:
                        logger.info(f"Found public S3 bucket: {bucket_name}")
                        return CloudIssue(
                            type="s3_bucket_public",
                            resource=f"{bucket_name}.s3.amazonaws.com",
                        )
                    # Check if it's a publicly readable bucket (might need specific key)
                    if "AccessDenied" not in response.text:
                        logger.info(f"Found accessible S3 bucket: {bucket_name}")
                        return CloudIssue(
                            type="s3_bucket_accessible",
                            resource=f"{bucket_name}.s3.amazonaws.com",
                        )

                # 403 might indicate bucket exists but is private (still interesting)
                if response.status_code == 403:
                    if "AccessDenied" in response.text and "ListBucket" in response.text:
                        # Bucket exists but listing is denied
                        logger.debug(f"S3 bucket exists but private: {bucket_name}")

        except (httpx.TimeoutException, httpx.RequestError):
            pass
        except Exception as e:
            logger.debug(f"Error checking S3 bucket {bucket_name}: {e}")

    return None


async def _check_azure_blob(storage_account: str, timeout: float) -> CloudIssue | None:
    """Check if an Azure Blob Storage container is public."""
    # Common container names to check
    containers = ["public", "assets", "uploads", "files", "data", "backup", "media"]

    for container in containers:
        url = f"https://{storage_account}.blob.core.windows.net/{container}?restype=container&comp=list"

        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    if "EnumerationResults" in response.text or "<Blob>" in response.text:
                        logger.info(f"Found public Azure blob: {storage_account}/{container}")
                        return CloudIssue(
                            type="azure_blob_public",
                            resource=f"{storage_account}.blob.core.windows.net/{container}",
                        )

        except (httpx.TimeoutException, httpx.RequestError):
            pass
        except Exception as e:
            logger.debug(f"Error checking Azure blob {storage_account}: {e}")

    return None


async def _check_gcs_bucket(bucket_name: str, timeout: float) -> CloudIssue | None:
    """Check if a Google Cloud Storage bucket is public."""
    url = f"https://storage.googleapis.com/{bucket_name}"

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(url)

            if response.status_code == 200:
                # Check for directory listing or content
                if "ListBucketResult" in response.text or "<Contents>" in response.text:
                    logger.info(f"Found public GCS bucket: {bucket_name}")
                    return CloudIssue(
                        type="gcs_bucket_public",
                        resource=f"storage.googleapis.com/{bucket_name}",
                    )

    except (httpx.TimeoutException, httpx.RequestError):
        pass
    except Exception as e:
        logger.debug(f"Error checking GCS bucket {bucket_name}: {e}")

    return None


def _extract_org_name(domain: str) -> str:
    """Extract organization name from domain."""
    parts = domain.lower().replace("-", "").replace("_", "").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain.replace(".", "")


def _generate_bucket_names(org_name: str, domain: str) -> list[str]:
    """Generate potential bucket names based on organization and domain."""
    names: set[str] = set()

    # Clean domain for bucket name (remove TLD)
    domain_parts = domain.lower().split(".")
    clean_domain = domain_parts[0] if domain_parts else domain

    for pattern in BUCKET_PATTERNS:
        name = pattern.format(org=org_name, domain=clean_domain)
        # S3 bucket names must be lowercase, 3-63 chars, no consecutive periods
        name = name.lower()
        name = re.sub(r"[^a-z0-9.-]", "-", name)
        name = re.sub(r"-+", "-", name)
        name = name.strip("-.")
        if 3 <= len(name) <= 63:
            names.add(name)

    # Also add variations with hyphens
    names.add(org_name)
    names.add(f"{org_name}-dev")
    names.add(f"{org_name}-prod")
    names.add(f"{org_name}-staging")

    return sorted(names)
