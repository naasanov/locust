"""
Integration tests for lateral movement tools against Juice Shop Docker container.

Prerequisites:
    docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

Run all tests (Gemini required for test 5):
    GEMINI_API_KEY=<key> pytest tests/lateral/test_lateral_integration.py -v

Run only tool tests (no Gemini / no Docker required for test 3):
    pytest tests/lateral/test_lateral_integration.py -v -k "not test_full_agent_run"

Cleanup:
    docker stop juice-shop && docker rm juice-shop
"""

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Skip guards — evaluated at collection time
# ---------------------------------------------------------------------------


def _juice_shop_up() -> bool:
    try:
        with socket.create_connection(("localhost", 3000), timeout=2):
            return True
    except OSError:
        return False


def _mysql_up() -> bool:
    try:
        with socket.create_connection(("localhost", 3306), timeout=2):
            return True
    except OSError:
        return False


def _wait_for_port(host: str, port: int, timeout_s: int = 30) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def _ensure_compose_services_running() -> str | None:
    """
    Best-effort autostart for local integration dependencies.

    Returns:
        None when services are reachable or startup is unnecessary,
        otherwise an error string used in skip reasons.
    """
    if _juice_shop_up() and _mysql_up():
        return None

    project_root = Path(__file__).resolve().parent.parent
    compose_file = project_root / "docker-compose.yml"
    if not compose_file.exists():
        return f"{compose_file} not found"

    try:
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "juice-shop", "mysql"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "docker CLI not found"
    except Exception as exc:  # pragma: no cover - defensive
        return f"docker compose startup raised: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"exit code {result.returncode}"
        return f"docker compose up failed: {detail}"

    if not _wait_for_port("localhost", 3000, timeout_s=45):
        return "Juice Shop did not become reachable on localhost:3000 in time"
    if not _wait_for_port("localhost", 3306, timeout_s=45):
        return "MySQL did not become reachable on localhost:3306 in time"

    return None


AUTO_START_ERROR = _ensure_compose_services_running()
JUICE_SHOP_AVAILABLE = _juice_shop_up()
MYSQL_AVAILABLE = _mysql_up()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

juice_shop_required = pytest.mark.skipif(
    not JUICE_SHOP_AVAILABLE,
    reason=(
        "Juice Shop not running on localhost:3000 "
        f"(autostart error: {AUTO_START_ERROR}) — start with: docker compose up -d"
    ),
)
mysql_required = pytest.mark.skipif(
    not MYSQL_AVAILABLE,
    reason=(
        "MySQL not running on localhost:3306 "
        f"(autostart error: {AUTO_START_ERROR}) — start with: docker compose up -d"
    ),
)
gemini_required = pytest.mark.skipif(
    not GEMINI_API_KEY,
    reason="GEMINI_API_KEY environment variable not set",
)

# ---------------------------------------------------------------------------
# Shared fixture: a realistic credential_exposure finding dict
# ---------------------------------------------------------------------------


def _make_finding_dict(
    vuln_class: str = "credential_exposure",
    response_snippet: str = (
        "DB_HOST=localhost\n"
        "DB_USER=juice_admin\n"
        "DB_PASSWORD=s3cr3tpass!\n"
        "NODE_ENV=production\n"
    ),
    affected_url: str = "http://localhost:3000/.env",
) -> dict:
    return {
        "engagement_id": "integ-test-001",
        "asset_id": "asset-localhost-3000",
        "finding_id": "finding-juice-001",
        "vulnerability_class": vuln_class,
        "title": "Exposed .env file with database credentials",
        "severity": "critical",
        "exploitable": True,
        "affected_url": affected_url,
        "evidence": {
            "request": "GET /.env HTTP/1.1\nHost: localhost:3000",
            "response_snippet": response_snippet,
            "status_code": 200,
        },
        "credentials_found": [],
        "blast_radius": "multi_asset",
    }


# ---------------------------------------------------------------------------
# Test 1: check_network_reachability
# ---------------------------------------------------------------------------


class TestNetworkReachabilityIntegration:
    """check_network_reachability against a live Juice Shop container."""

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_juice_shop_port_3000_open(self):
        """Juice Shop exposes port 3000 — assert reachable=True and 3000 in open_ports."""
        from src.agents.lateral.tools import check_network_reachability

        result = await check_network_reachability(
            from_asset="attacker-machine",
            to_asset="localhost",
        )

        assert result["reachable"] is True
        assert 3000 in result["open_ports"]
        assert result["target"] == "localhost"
        assert result["from"] == "attacker-machine"
        assert result["method"] == "tcp_connect"
        assert isinstance(result["open_ports"], list)

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_url_scheme_stripped(self):
        """to_asset may be a full URL — host should be extracted correctly."""
        from src.agents.lateral.tools import check_network_reachability

        result = await check_network_reachability(
            from_asset="entry-point",
            to_asset="http://localhost:3000/.env",
        )

        # Host extracted from URL; port 3000 still open
        assert result["target"] == "localhost"
        assert 3000 in result["open_ports"]


# ---------------------------------------------------------------------------
# Test 2: enumerate_credentials
# ---------------------------------------------------------------------------


class TestEnumerateCredentialsIntegration:
    """enumerate_credentials against a live Juice Shop container."""

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_parses_env_snippet(self):
        """Regex parsing picks up DB_USER and DB_PASSWORD from .env-style snippet."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding_dict()
        result = await enumerate_credentials(host="localhost", finding=finding)

        assert result["vulnerability_class"] == "credential_exposure"
        creds = result["credentials_parsed"]
        assert isinstance(creds, list)

        types_found = {c["type"] for c in creds}
        # Both username and password patterns should match
        assert "key_value_user" in types_found, f"key_value_user not found in: {types_found}"
        assert "key_value_pass" in types_found, f"key_value_pass not found in: {types_found}"

    @mysql_required
    @pytest.mark.asyncio
    async def test_mysql_connection_succeeds(self):
        """MySQL container is running — connection with juice_admin/s3cr3tpass! must succeed."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding_dict()
        result = await enumerate_credentials(host="localhost", finding=finding)

        conn_results = result["connection_results"]
        assert isinstance(conn_results, list)

        mysql_results = [r for r in conn_results if r.get("service") == "mysql"]
        assert len(mysql_results) == 1, (
            f"Expected 1 mysql connection result, got: {conn_results}"
        )
        assert mysql_results[0]["success"] is True, (
            f"Expected MySQL connection to succeed, got: {mysql_results[0]}"
        )
        assert mysql_results[0]["host"] == "localhost"

    @mysql_required
    @pytest.mark.asyncio
    async def test_creds_verified_on_successful_connection(self):
        """At least the password credential must be verified=True after MySQL connects."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding_dict()
        result = await enumerate_credentials(host="localhost", finding=finding)

        verified = [c for c in result["credentials_parsed"] if c["verified"] is True]
        assert len(verified) >= 1, (
            f"Expected at least 1 verified credential, got: {result['credentials_parsed']}"
        )


# ---------------------------------------------------------------------------
# Test 3: check_iam_permissions (no Docker required)
# ---------------------------------------------------------------------------


class TestCheckIamPermissionsIntegration:
    """check_iam_permissions without real AWS credentials."""

    @pytest.mark.asyncio
    async def test_no_creds_in_finding_returns_errors(self):
        """Without AWS creds, all five boto3 calls fail — errors dict is populated."""
        from src.agents.lateral.tools import check_iam_permissions

        result = await check_iam_permissions(
            service="us-east-1",
            finding={"credentials_found": []},
        )

        # All five keys always present
        for key in ("identity", "s3_buckets", "secrets", "iam_user", "ec2_instances", "errors"):
            assert key in result, f"Missing key: {key}"

        assert isinstance(result["s3_buckets"], list)
        assert isinstance(result["ec2_instances"], list)
        assert isinstance(result["errors"], dict)
        # No valid AWS creds → at minimum STS call fails
        assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_non_region_service_hint_defaults(self):
        """'sts' (not a region string) should not crash — falls back to us-east-1."""
        from src.agents.lateral.tools import check_iam_permissions

        result = await check_iam_permissions(
            service="sts",
            finding={"credentials_found": []},
        )

        assert "errors" in result
        # Should still attempt calls and get errors (not raise)
        assert isinstance(result["errors"], dict)


# ---------------------------------------------------------------------------
# Test 4: identify_sensitive_stores
# ---------------------------------------------------------------------------


class TestIdentifySensitiveStoresIntegration:
    """identify_sensitive_stores against a live Juice Shop container."""

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_result_shape(self):
        """Result always has the three expected keys."""
        from src.agents.lateral.tools import identify_sensitive_stores

        result = await identify_sensitive_stores(
            host="localhost",
            reachable_assets=[],
            finding=_make_finding_dict(),
        )

        assert "db_ports_found" in result
        assert "admin_interfaces" in result
        assert "summary" in result
        assert isinstance(result["db_ports_found"], list)
        assert isinstance(result["admin_interfaces"], list)
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    @mysql_required
    @pytest.mark.asyncio
    async def test_mysql_port_3306_found(self):
        """MySQL container is running — port 3306 must appear in db_ports_found."""
        from src.agents.lateral.tools import identify_sensitive_stores

        result = await identify_sensitive_stores(
            host="localhost",
            reachable_assets=[],
            finding=_make_finding_dict(),
        )

        open_db_ports = {r["port"] for r in result["db_ports_found"]}
        assert 3306 in open_db_ports, (
            f"Expected MySQL port 3306 in db_ports_found, got: {open_db_ports}"
        )
        mysql_entry = next(r for r in result["db_ports_found"] if r["port"] == 3306)
        assert mysql_entry["service"] == "mysql"
        assert mysql_entry["host"] == "localhost"

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_admin_interfaces_have_valid_status_codes(self):
        """Any admin interface found must have a status code in (200, 401, 403)."""
        from src.agents.lateral.tools import identify_sensitive_stores

        result = await identify_sensitive_stores(
            host="localhost",
            reachable_assets=[],
            finding=_make_finding_dict(),
        )

        for iface in result["admin_interfaces"]:
            assert iface["status_code"] in (200, 401, 403), (
                f"Unexpected status code {iface['status_code']} for {iface['url']}"
            )

    @juice_shop_required
    @pytest.mark.asyncio
    async def test_deduplication_with_reachable_assets(self):
        """Duplicate hosts between host and reachable_assets are scanned only once."""
        from src.agents.lateral.tools import identify_sensitive_stores

        # Pass localhost twice — once as host, once in reachable_assets
        result_deduped = await identify_sensitive_stores(
            host="localhost",
            reachable_assets=["localhost"],
            finding=_make_finding_dict(),
        )
        result_single = await identify_sensitive_stores(
            host="localhost",
            reachable_assets=[],
            finding=_make_finding_dict(),
        )

        # Both calls should produce the same db_ports_found count
        assert len(result_deduped["db_ports_found"]) == len(result_single["db_ports_found"])


# ---------------------------------------------------------------------------
# Test 5: Full LateralAgent.run() with real Gemini
# ---------------------------------------------------------------------------


class TestLateralAgentFullRunIntegration:
    """End-to-end test: LateralAgent.run() using real Gemini API against Juice Shop."""

    @juice_shop_required
    @mysql_required
    @gemini_required
    @pytest.mark.asyncio
    async def test_produces_attack_chain(self):
        """
        Full Gemini reasoning cycle produces a valid AttackChain for a
        credential_exposure finding with a live MySQL pivot target.
        """
        from src.agents.lateral.agent import LateralAgent
        from src.models.asset import AssetDocument
        from src.models.finding import Evidence, FindingDocument, LateralAgentInput

        finding = FindingDocument(
            engagement_id="integ-test-001",
            asset_id="asset-localhost-3000",
            finding_id="finding-juice-001",
            vulnerability_class="credential_exposure",
            title="Exposed .env file with database credentials",
            severity="critical",
            exploitable=True,
            affected_url="http://localhost:3000/.env",
            evidence=Evidence(
                request="GET /.env HTTP/1.1\nHost: localhost:3000",
                response_snippet=(
                    "DB_HOST=localhost\n"
                    "DB_USER=juice_admin\n"
                    "DB_PASSWORD=s3cr3tpass!\n"
                    "NODE_ENV=production\n"
                ),
                status_code=200,
            ),
            blast_radius="multi_asset",
        )

        asset = AssetDocument(
            engagement_id="integ-test-001",
            asset_type="web_app",
            url="http://localhost:3000",
            ip="127.0.0.1",
            open_ports=[3000],
            attack_surface_score=0.85,
            score_reasoning="Web app with exposed .env file",
        )

        agent = LateralAgent(api_key=GEMINI_API_KEY)
        chains = await agent.run(
            LateralAgentInput(findings=[finding], asset_graph=[asset])
        )

        assert len(chains) == 1, f"Expected 1 chain, got {len(chains)}"
        chain = chains[0]

        assert chain.engagement_id == "integ-test-001"
        assert chain.entry_point_finding_id == "finding-juice-001"
        assert chain.entry_point is not None
        assert chain.entry_point != ""
        assert len(chain.pivot_path) >= 1, "Expected at least 1 pivot step"
        assert chain.blast_radius_summary != "", "Expected non-empty blast radius summary"
        assert 0.0 <= chain.blast_radius_score <= 1.0

        # With a real MySQL target, Gemini should find a sensitive store
        assert len(chain.reachable_sensitive_stores) >= 1, (
            "Expected at least 1 sensitive store (MySQL on port 3306)"
        )
        assert chain.blast_radius_score >= 0.5, (
            f"Expected high blast radius score with verified DB access, "
            f"got: {chain.blast_radius_score}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
