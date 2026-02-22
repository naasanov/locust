"""Lateral movement tools for the LateralAgent.

Each function is self-contained and swappable. Blocking I/O (pymysql, boto3) runs in
asyncio.get_event_loop().run_in_executor() so the async loop stays free.
"""

import asyncio
import logging
import re
from urllib.parse import urlparse

import boto3
import httpx
import pymysql

logger = logging.getLogger(__name__)

# Always True since both are now required deps in pyproject.toml.
# Still used as flags so tests can monkeypatch them to simulate missing deps.
_PYMYSQL_AVAILABLE = True
_BOTO3_AVAILABLE = True

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DB_PORTS: list[int] = [3306, 5432, 27017, 6379, 9200, 2375]

DB_PORT_NAMES: dict[int, str] = {
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb",
    6379: "redis",
    9200: "elasticsearch",
    2375: "docker-api",
}

REACHABILITY_PORTS: list[int] = DB_PORTS + [22, 80, 443, 8080, 8443, 3000, 5000, 8000]

ADMIN_PATHS: list[str] = [
    "/phpmyadmin",
    "/phpmyadmin/",
    "/_cat/indices",
    "/_cluster/health",
    "/adminer",
    "/adminer.php",
    "/manager/html",
    "/console",
    "/wp-admin",
    "/admin",
    "/administrator",
    "/.env",
    "/actuator",
    "/actuator/env",
    "/api/v1",
    "/redis",
]

# Credential regex patterns: (label, compiled_pattern)
# Ordered from most specific to least specific to reduce false positives.
CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mysql_dsn", re.compile(r"mysql://([^:]+):([^@]+)@([^/\s]+)", re.IGNORECASE)),
    (
        "postgres_dsn",
        re.compile(r"postgres(?:ql)?://([^:]+):([^@]+)@([^/\s]+)", re.IGNORECASE),
    ),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}")),
    (
        "aws_secret_key",
        re.compile(
            r'(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})',
            re.IGNORECASE,
        ),
    ),
    (
        "key_value_pass",
        re.compile(
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>\n]{6,})',
            re.IGNORECASE,
        ),
    ),
    (
        "key_value_user",
        re.compile(
            r'(?:username|user|login)\s*[=:]\s*["\']?([^\s"\'<>\n]{3,})',
            re.IGNORECASE,
        ),
    ),
    (
        "api_key",
        re.compile(
            r'(?:api[_-]?key|apikey|token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
            re.IGNORECASE,
        ),
    ),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

_CAPTURED_VALUE_TYPES: set[str] = {
    "aws_secret_key",
    "key_value_pass",
    "key_value_user",
    "api_key",
}


# ---------------------------------------------------------------------------
# Tool 1: check_network_reachability
# ---------------------------------------------------------------------------


async def check_network_reachability(from_asset: str, to_asset: str) -> dict:
    """
    Real TCP-connect probe to determine which ports on to_asset are open.

    Probing runs from the agent's host (the operator's machine), which should
    have network access to the target. from_asset is used for labelling only.

    Returns:
        {
            "reachable": bool,
            "open_ports": list[int],
            "method": "tcp_connect",
            "target": str,
            "from": str,
        }
    """
    host = _parse_host(to_asset)
    logger.info(
        f"Reachability probe {from_asset} → {host} ({len(REACHABILITY_PORTS)} ports)"
    )

    tasks = [_probe_port(host, port) for port in REACHABILITY_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = [
        port for port, result in zip(REACHABILITY_PORTS, results) if result is True
    ]

    logger.info(f"Reachability {host}: {len(open_ports)} open ports {open_ports}")
    return {
        "reachable": len(open_ports) > 0,
        "open_ports": sorted(open_ports),
        "method": "tcp_connect",
        "target": host,
        "from": from_asset,
    }


async def _probe_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Attempt a TCP connection; return True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _parse_host(asset: str) -> str:
    """Extract hostname/IP from an asset identifier (strips scheme and path)."""
    if "://" not in asset:
        asset = "tcp://" + asset
    parsed = urlparse(asset)
    return parsed.hostname or asset


# ---------------------------------------------------------------------------
# Tool 2: enumerate_credentials
# ---------------------------------------------------------------------------


async def enumerate_credentials(host: str, finding: dict) -> dict:
    """
    Parse credentials from finding evidence and attempt live verification.

    Behavior by vulnerability_class:
      - "credential_exposure": regex-parse response_snippet, attempt live
        pymysql / boto3 connections (REAL).
      - "sql_injection": structured stub — this is where sqlmap would integrate
        (STUB, see comment in code).
      - All others: regex parse only, no connection attempt.

    Args:
        host:    Target hostname or IP.
        finding: FindingDocument serialized as dict (injected by dispatcher).

    Returns:
        {
            "credentials_parsed": list[dict],
            "connection_results": list[dict],
            "vulnerability_class": str,
        }
    """
    normalized_host = _parse_host(host)
    vuln_class = finding.get("vulnerability_class", "")
    response_snippet = finding.get("evidence", {}).get("response_snippet", "")

    if vuln_class == "sql_injection":
        # STUB: sqlmap integration point.
        # In production: shell out to `sqlmap -u <url> --dump --batch --output-dir=/tmp/sqlmap_out`
        # and parse the resulting CSV files for extracted database credentials.
        # sqlmap would handle all injection type variations (UNION, error-based, blind, etc.)
        # and return structured credential data from every accessible table.
        affected_url = finding.get("affected_url", "unknown")
        return {
            "credentials_parsed": [],
            "connection_results": [
                {
                    "service": "sqlmap",
                    "host": normalized_host,
                    "status": "stub",
                    "detail": (
                        f"SQL injection confirmed on {affected_url}. "
                        "sqlmap --dump would extract DB credentials here. "
                        "Integration pending: shell out to sqlmap and parse output CSV."
                    ),
                }
            ],
            "vulnerability_class": "sql_injection",
        }

    # Parse credentials from response snippet
    credentials_parsed = _parse_credential_patterns(response_snippet)

    # Also check credentials_found list in the finding itself
    for cred in finding.get("credentials_found", []):
        cred_value = cred.get("value", "")
        cred_type = cred.get("type", "unknown")
        if cred_value and not any(c["value"] == cred_value for c in credentials_parsed):
            credentials_parsed.append(
                {
                    "type": cred_type,
                    "value": cred_value,
                    "verified": False,
                    "source": "credentials_found",
                }
            )

    connection_results: list[dict] = []

    if vuln_class == "credential_exposure":
        connection_results = await _attempt_connections(normalized_host, credentials_parsed)

    return {
        "credentials_parsed": credentials_parsed,
        "connection_results": connection_results,
        "vulnerability_class": vuln_class,
    }


def _parse_credential_patterns(text: str) -> list[dict]:
    """Run all CREDENTIAL_PATTERNS against text and return matched credentials."""
    found: list[dict] = []
    seen: set[str] = set()

    for label, pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if label in _CAPTURED_VALUE_TYPES and match.lastindex:
                value = match.group(1)
            if value not in seen:
                seen.add(value)
                found.append(
                    {
                        "type": label,
                        "value": value,
                        "verified": False,
                        "source": "response_snippet",
                    }
                )

    return found


async def _attempt_connections(host: str, credentials: list[dict]) -> list[dict]:
    """Attempt live connections using parsed credentials."""
    results: list[dict] = []
    loop = asyncio.get_event_loop()

    # Group credentials by type for targeted connection attempts
    mysql_creds = _extract_db_creds(credentials, ["mysql_dsn", "key_value_pass"])
    aws_key = _extract_aws_key(credentials)
    aws_secret = _extract_aws_secret(credentials)

    # MySQL connection attempt
    if mysql_creds:
        user, password = mysql_creds
        result = await loop.run_in_executor(
            None, _try_mysql_connect, host, user, password
        )
        results.append(result)
        # Mark credentials as verified on success
        if result.get("success"):
            for c in credentials:
                if c["type"] in ("mysql_dsn", "key_value_pass", "key_value_user"):
                    c["verified"] = True
    elif mysql_creds:
        logger.warning("pymysql not installed — skipping MySQL connection attempt")
        results.append(
            {
                "service": "mysql",
                "host": host,
                "status": "skipped",
                "detail": "pymysql not installed. Install with: pip install pymysql",
                "success": False,
            }
        )

    # AWS credential verification
    if aws_key and aws_secret:
        if _BOTO3_AVAILABLE:
            result = await loop.run_in_executor(None, _try_aws_sts, aws_key, aws_secret)
            results.append(result)
            if result.get("success"):
                for c in credentials:
                    if c["type"] in ("aws_access_key", "aws_secret_key"):
                        c["verified"] = True
        else:
            logger.warning("boto3 not installed — skipping AWS credential verification")
            results.append(
                {
                    "service": "aws_sts",
                    "host": "aws",
                    "status": "skipped",
                    "detail": "boto3 not installed. Install with: pip install boto3",
                    "success": False,
                }
            )

    return results


def _extract_db_creds(
    credentials: list[dict], types: list[str]
) -> tuple[str, str] | None:
    """Extract (username, password) from credential list."""
    user = None
    password = None

    for cred in credentials:
        if cred["type"] == "mysql_dsn":
            # mysql://user:pass@host — value is the full DSN
            match = re.match(r"mysql://([^:]+):([^@]+)@", cred["value"], re.IGNORECASE)
            if match:
                return match.group(1), match.group(2)

        if cred["type"] == "key_value_user" and user is None:
            # Strip surrounding quotes
            user = cred["value"].strip("'\"")
        if cred["type"] == "key_value_pass" and password is None:
            password = cred["value"].strip("'\"")

    if user and password:
        return user, password
    if password:
        return "root", password  # Common default when only password is found
    return None


def _extract_aws_key(credentials: list[dict]) -> str | None:
    """Extract AWS access key ID from credentials list."""
    for c in credentials:
        if c["type"] == "aws_access_key":
            return c["value"]
    return None


def _extract_aws_secret(credentials: list[dict]) -> str | None:
    """Extract AWS secret access key value from credentials list."""
    for c in credentials:
        if c["type"] == "aws_secret_key":
            # The regex captures the secret value in group 1
            match = re.search(
                r'(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})',
                c["value"],
                re.IGNORECASE,
            )
            if match:
                return match.group(1)
            # Might already be just the 40-char secret
            if len(c["value"]) == 40:
                return c["value"]
    return None


def _try_mysql_connect(host: str, user: str, password: str) -> dict:
    """Synchronous MySQL connection attempt (runs in executor)."""
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            connect_timeout=3,
            read_timeout=3,
        )
        # Get visible databases
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        databases = [row[0] for row in cursor.fetchall()]
        conn.close()
        logger.info(f"MySQL connection to {host} succeeded. Databases: {databases}")
        return {
            "service": "mysql",
            "host": host,
            "port": 3306,
            "status": "connected",
            "detail": f"Connected as {user}. Visible databases: {databases}",
            "success": True,
        }
    except Exception as e:
        return {
            "service": "mysql",
            "host": host,
            "port": 3306,
            "status": "failed",
            "detail": str(e),
            "success": False,
        }


def _try_aws_sts(access_key: str, secret_key: str) -> dict:
    """Synchronous AWS STS identity check (runs in executor)."""
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        identity = session.client("sts").get_caller_identity()
        logger.info(f"AWS credentials valid. Identity: {identity.get('Arn')}")
        return {
            "service": "aws_sts",
            "host": "aws",
            "status": "valid",
            "detail": f"Caller identity: {identity.get('Arn')} (Account: {identity.get('Account')})",
            "identity": {
                "arn": identity.get("Arn"),
                "account": identity.get("Account"),
                "user_id": identity.get("UserId"),
            },
            "success": True,
        }
    except Exception as e:
        return {
            "service": "aws_sts",
            "host": "aws",
            "status": "invalid",
            "detail": str(e),
            "success": False,
        }


# ---------------------------------------------------------------------------
# Tool 3: check_iam_permissions
# ---------------------------------------------------------------------------


async def check_iam_permissions(service: str, finding: dict) -> dict:
    """
    Real boto3 calls to enumerate what IAM permissions leaked credentials grant.

    Each AWS service check runs independently — a failure on one does not abort
    the others. Results include partial data from successful checks.

    Args:
        service: AWS region hint (e.g. "us-east-1") or service name. Used as
                 boto3 region_name when it looks like a region; defaults to
                 "us-east-1" otherwise.
        finding: FindingDocument serialized as dict (injected by dispatcher).

    Returns:
        {
            "identity": dict | None,
            "s3_buckets": list[str],
            "secrets": list[str],
            "iam_user": str | None,
            "ec2_instances": list[str],
            "errors": dict[str, str],
        }
    """
    if not _BOTO3_AVAILABLE:
        return {
            "identity": None,
            "s3_buckets": [],
            "secrets": [],
            "iam_user": None,
            "ec2_instances": [],
            "errors": {
                "boto3": "boto3 not installed — install with: pip install boto3"
            },
        }

    # Determine AWS region from the service hint
    region = service if _looks_like_region(service) else "us-east-1"

    # Extract credentials from the finding
    access_key, secret_key = _extract_aws_creds_from_finding(finding)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, _check_iam_sync, region, access_key, secret_key
    )
    return result


def _looks_like_region(s: str) -> bool:
    """Check if string looks like an AWS region identifier."""
    return bool(re.match(r"^[a-z]{2}-[a-z]+-\d$", s))


def _extract_aws_creds_from_finding(finding: dict) -> tuple[str | None, str | None]:
    """Extract AWS access key and secret from finding's credentials_found list."""
    access_key = None
    secret_key = None

    for cred in finding.get("credentials_found", []):
        cred_type = cred.get("type", "").lower()
        value = cred.get("value", "")
        if "aws" in cred_type and "access" in cred_type and not access_key:
            # Extract the key ID if it's in "KEY=AKIA..." format
            match = re.search(r"((?:AKIA|ASIA|AROA)[A-Z0-9]{16})", value)
            access_key = match.group(1) if match else value
        elif "aws" in cred_type and "secret" in cred_type and not secret_key:
            match = re.search(r"[A-Za-z0-9/+]{40}", value)
            secret_key = match.group(0) if match else value

    return access_key, secret_key


def _check_iam_sync(
    region: str,
    access_key: str | None,
    secret_key: str | None,
) -> dict:
    """Synchronous IAM permission checks (runs in executor)."""
    result: dict = {
        "identity": None,
        "s3_buckets": [],
        "secrets": [],
        "iam_user": None,
        "ec2_instances": [],
        "errors": {},
    }

    # Build session — explicit creds if available, default chain otherwise
    session_kwargs: dict = {"region_name": region}
    if access_key and secret_key:
        session_kwargs["aws_access_key_id"] = access_key
        session_kwargs["aws_secret_access_key"] = secret_key

    session = boto3.Session(**session_kwargs)

    # STS: get caller identity
    try:
        sts = session.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        result["identity"] = {
            "arn": identity.get("Arn"),
            "account": identity.get("Account"),
            "user_id": identity.get("UserId"),
        }
        logger.info(f"IAM identity: {identity.get('Arn')}")
    except Exception as e:
        result["errors"]["sts"] = str(e)

    # S3: list buckets
    try:
        s3 = session.client("s3", region_name=region)
        response = s3.list_buckets()
        result["s3_buckets"] = [b["Name"] for b in response.get("Buckets", [])]
        logger.info(f"S3 buckets accessible: {result['s3_buckets']}")
    except Exception as e:
        result["errors"]["s3"] = str(e)

    # Secrets Manager: list secrets
    try:
        sm = session.client("secretsmanager", region_name=region)
        response = sm.list_secrets(MaxResults=10)
        result["secrets"] = [s["Name"] for s in response.get("SecretList", [])]
        logger.info(f"Secrets Manager entries: {result['secrets']}")
    except Exception as e:
        result["errors"]["secretsmanager"] = str(e)

    # IAM: get current user
    try:
        iam = session.client("iam", region_name=region)
        user = iam.get_user()
        result["iam_user"] = user.get("User", {}).get("UserName")
        logger.info(f"IAM user: {result['iam_user']}")
    except Exception as e:
        result["errors"]["iam"] = str(e)

    # EC2: describe instances
    try:
        ec2 = session.client("ec2", region_name=region)
        response = ec2.describe_instances(MaxResults=5)
        instance_ids = [
            i["InstanceId"]
            for r in response.get("Reservations", [])
            for i in r.get("Instances", [])
        ]
        result["ec2_instances"] = instance_ids
        logger.info(f"EC2 instances visible: {instance_ids}")
    except Exception as e:
        result["errors"]["ec2"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Tool 4: identify_sensitive_stores
# ---------------------------------------------------------------------------


async def identify_sensitive_stores(
    host: str,
    reachable_assets: list[str],
    finding: dict,
) -> dict:
    """
    Real port scan for database services and HTTP probe for admin interfaces.

    Args:
        host:             Primary target hostname or IP.
        reachable_assets: Additional hosts discovered via check_network_reachability.
        finding:          FindingDocument serialized as dict (injected by dispatcher).

    Returns:
        {
            "db_ports_found": list[dict],    # [{host, port, service}]
            "admin_interfaces": list[dict],  # [{host, path, status_code, url}]
            "summary": str,
        }
    """
    all_targets = list(
        dict.fromkeys([_parse_host(host)] + [_parse_host(a) for a in reachable_assets])
    )
    logger.info(
        f"Scanning {len(all_targets)} targets for sensitive stores: {all_targets}"
    )

    # Run DB port scan and admin interface probe concurrently
    db_task = asyncio.create_task(_scan_db_ports(all_targets))
    admin_task = asyncio.create_task(_probe_admin_interfaces(all_targets))

    db_ports_found, admin_interfaces = await asyncio.gather(db_task, admin_task)

    summary_parts = []
    if db_ports_found:
        services = ", ".join(
            f"{r['host']}:{r['port']} ({r['service']})" for r in db_ports_found
        )
        summary_parts.append(f"Database ports open: {services}")
    if admin_interfaces:
        paths = ", ".join(
            f"{r['host']}{r['path']} ({r['status_code']})" for r in admin_interfaces
        )
        summary_parts.append(f"Admin interfaces found: {paths}")
    if not summary_parts:
        summary_parts.append(
            "No database ports or admin interfaces found on scanned targets"
        )

    return {
        "db_ports_found": db_ports_found,
        "admin_interfaces": admin_interfaces,
        "summary": ". ".join(summary_parts) + ".",
    }


async def _scan_db_ports(targets: list[str]) -> list[dict]:
    """Probe DB_PORTS on each target concurrently."""
    tasks = [(target, port) for target in targets for port in DB_PORTS]
    results = await asyncio.gather(
        *[_probe_port(target, port) for target, port in tasks],
        return_exceptions=True,
    )

    found = []
    for (target, port), result in zip(tasks, results):
        if result is True:
            found.append(
                {
                    "host": target,
                    "port": port,
                    "service": DB_PORT_NAMES.get(port, "unknown"),
                }
            )
            logger.info(f"DB port open: {target}:{port} ({DB_PORT_NAMES.get(port)})")

    return found


async def _probe_admin_interfaces(targets: list[str]) -> list[dict]:
    """HTTP-probe ADMIN_PATHS on each target. Considers 200, 401, 403 as 'found'."""
    found: list[dict] = []
    semaphore = asyncio.Semaphore(10)

    async def probe_one(target: str, path: str) -> dict | None:
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}{path}"
            async with semaphore:
                try:
                    async with httpx.AsyncClient(
                        verify=False,
                        timeout=3.0,
                        follow_redirects=False,
                    ) as client:
                        response = await client.get(url)
                        if response.status_code in (200, 401, 403):
                            logger.info(
                                f"Admin interface found: {url} ({response.status_code})"
                            )
                            return {
                                "host": target,
                                "path": path,
                                "status_code": response.status_code,
                                "url": url,
                            }
                except Exception:
                    pass
        return None

    probe_tasks = [
        probe_one(target, path) for target in targets for path in ADMIN_PATHS
    ]
    results = await asyncio.gather(*probe_tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict):
            found.append(result)

    return found
