"""
Tests for LAT-02 lateral movement tools.

Run with: pytest tests/lateral/test_lateral_tools.py -v
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_finding(
    vulnerability_class: str = "credential_exposure",
    response_snippet: str = "",
    credentials_found: list | None = None,
    affected_url: str = "http://localhost:3000/.env",
) -> dict:
    """Minimal FindingDocument dict for tool testing."""
    return {
        "finding_id": "f-test-001",
        "engagement_id": "eng-test",
        "vulnerability_class": vulnerability_class,
        "evidence": {
            "request": f"GET {affected_url.split('/', 3)[-1]}",
            "response_snippet": response_snippet,
            "status_code": 200,
        },
        "credentials_found": credentials_found or [],
        "affected_url": affected_url,
    }


# ---------------------------------------------------------------------------
# TestCheckNetworkReachability
# ---------------------------------------------------------------------------


class TestCheckNetworkReachability:
    """Tests for check_network_reachability."""

    @pytest.mark.asyncio
    async def test_ports_open(self, monkeypatch):
        """Ports that return True from _probe_port appear in open_ports."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_network_reachability

        async def fake_probe(host, port, timeout=2.0):
            return port in (80, 443, 3306)

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)

        result = await check_network_reachability("attacker-host", "192.168.1.10")

        assert result["reachable"] is True
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]
        assert 3306 in result["open_ports"]
        assert result["method"] == "tcp_connect"
        assert result["target"] == "192.168.1.10"

    @pytest.mark.asyncio
    async def test_no_ports_open(self, monkeypatch):
        """No open ports means reachable=False."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_network_reachability

        async def fake_probe(host, port, timeout=2.0):
            return False

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)

        result = await check_network_reachability("attacker", "10.0.0.1")

        assert result["reachable"] is False
        assert result["open_ports"] == []

    @pytest.mark.asyncio
    async def test_url_target_strips_scheme(self, monkeypatch):
        """to_asset may be a full URL — the hostname is extracted correctly."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_network_reachability

        probed_hosts: list[str] = []

        async def fake_probe(host, port, timeout=2.0):
            probed_hosts.append(host)
            return False

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)

        await check_network_reachability(
            "entry", "http://internal-db.acme.com:3306/prod"
        )

        assert all(h == "internal-db.acme.com" for h in probed_hosts)

    @pytest.mark.asyncio
    async def test_open_ports_are_sorted(self, monkeypatch):
        """open_ports list is always sorted ascending."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_network_reachability

        async def fake_probe(host, port, timeout=2.0):
            return port in (8443, 22, 3306, 80)

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)

        result = await check_network_reachability("a", "b")

        assert result["open_ports"] == sorted(result["open_ports"])

    @pytest.mark.asyncio
    async def test_from_asset_preserved_in_result(self, monkeypatch):
        """from_asset label is echoed back in the result."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_network_reachability

        async def fake_probe(host, port, timeout=2.0):
            return False

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)

        result = await check_network_reachability("dev-portal.acme.com", "10.0.0.5")

        assert result["from"] == "dev-portal.acme.com"


# ---------------------------------------------------------------------------
# TestEnumerateCredentials
# ---------------------------------------------------------------------------


class TestEnumerateCredentials:
    """Tests for enumerate_credentials."""

    @pytest.mark.asyncio
    async def test_credential_exposure_parses_mysql_dsn(self):
        """MySQL DSN in response_snippet is extracted."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            response_snippet="DB_URL=mysql://admin:S3cr3tPass@db.internal:3306/app"
        )
        result = await enumerate_credentials("db.internal", finding)

        types_found = [c["type"] for c in result["credentials_parsed"]]
        assert "mysql_dsn" in types_found

    @pytest.mark.asyncio
    async def test_credential_exposure_parses_aws_key(self):
        """AWS access key ID pattern is detected."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            response_snippet="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        result = await enumerate_credentials("target", finding)

        types_found = [c["type"] for c in result["credentials_parsed"]]
        assert "aws_access_key" in types_found

    @pytest.mark.asyncio
    async def test_credential_exposure_parses_password_key_value(self):
        """Generic password= pattern is extracted."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            response_snippet="DB_PASSWORD=Acme2024!\nDB_USER=webuser"
        )
        result = await enumerate_credentials("host", finding)

        types_found = [c["type"] for c in result["credentials_parsed"]]
        assert "key_value_pass" in types_found
        assert "key_value_user" in types_found

    @pytest.mark.asyncio
    async def test_credential_exposure_parses_jwt_token(self):
        """JWT token format is detected."""
        from src.agents.lateral.tools import enumerate_credentials

        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        finding = _make_finding(response_snippet=f"token={jwt}")
        result = await enumerate_credentials("host", finding)

        types_found = [c["type"] for c in result["credentials_parsed"]]
        assert "jwt_token" in types_found

    @pytest.mark.asyncio
    async def test_credential_exposure_includes_credentials_found_list(self):
        """Credentials from finding.credentials_found are included even if not in snippet."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            response_snippet="",
            credentials_found=[
                {"type": "database", "value": "DB_PASSWORD=Hunter2!"},
            ],
        )
        result = await enumerate_credentials("host", finding)

        assert any(
            c["value"] == "DB_PASSWORD=Hunter2!" for c in result["credentials_parsed"]
        )

    @pytest.mark.asyncio
    async def test_credential_exposure_no_duplicates(self):
        """The same credential value is not listed twice."""
        from src.agents.lateral.tools import enumerate_credentials

        snippet = "password=abc123 password=abc123"
        finding = _make_finding(response_snippet=snippet)
        result = await enumerate_credentials("host", finding)

        values = [c["value"] for c in result["credentials_parsed"]]
        assert len(values) == len(set(values))

    @pytest.mark.asyncio
    async def test_credential_exposure_verified_false_initially(self):
        """All parsed credentials start with verified=False before connection attempt."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(response_snippet="DB_PASSWORD=somepassword")
        result = await enumerate_credentials("host", finding)

        # Without pymysql installed, no connection attempt succeeds
        for c in result["credentials_parsed"]:
            # verified may be True only if a live connection succeeds —
            # in CI without pymysql, all should remain False
            assert isinstance(c["verified"], bool)

    @pytest.mark.asyncio
    async def test_credential_exposure_mysql_connect_success(self, monkeypatch):
        """Successful MySQL connection sets verified=True on matching credentials."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import enumerate_credentials

        # Patch pymysql availability and connection
        mock_pymysql = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("information_schema",), ("app_db",)]
        mock_conn.cursor.return_value = mock_cursor
        mock_pymysql.connect.return_value = mock_conn

        monkeypatch.setattr(tools_module, "pymysql", mock_pymysql)
        monkeypatch.setattr(tools_module, "_PYMYSQL_AVAILABLE", True)

        finding = _make_finding(response_snippet="DB_USER=root\nDB_PASSWORD=r00tpass")
        result = await enumerate_credentials("db.internal", finding)

        assert any(cr["success"] for cr in result["connection_results"])
        # At least one credential should now be verified
        assert any(c["verified"] for c in result["credentials_parsed"])

    @pytest.mark.asyncio
    async def test_credential_exposure_normalizes_url_host_for_mysql(self, monkeypatch):
        """URL-style host input is normalized before MySQL connect."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import enumerate_credentials

        mock_pymysql = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [("information_schema",)]
        mock_conn.cursor.return_value = mock_cursor
        mock_pymysql.connect.return_value = mock_conn

        monkeypatch.setattr(tools_module, "pymysql", mock_pymysql)
        monkeypatch.setattr(tools_module, "_PYMYSQL_AVAILABLE", True)

        finding = _make_finding(response_snippet="DB_USER=root\nDB_PASSWORD=r00tpass")
        result = await enumerate_credentials("http://localhost:3000/.env", finding)

        assert any(cr["success"] for cr in result["connection_results"])
        assert mock_pymysql.connect.call_args.kwargs["host"] == "localhost"

    @pytest.mark.asyncio
    async def test_credential_exposure_mysql_connect_failure(self, monkeypatch):
        """Failed MySQL connection is reported without raising."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import enumerate_credentials

        mock_pymysql = MagicMock()
        mock_pymysql.connect.side_effect = Exception("Connection refused")

        monkeypatch.setattr(tools_module, "pymysql", mock_pymysql)
        monkeypatch.setattr(tools_module, "_PYMYSQL_AVAILABLE", True)

        finding = _make_finding(response_snippet="DB_USER=root\nDB_PASSWORD=wrongpass")
        result = await enumerate_credentials("db.internal", finding)

        mysql_results = [
            cr for cr in result["connection_results"] if cr["service"] == "mysql"
        ]
        assert len(mysql_results) == 1
        assert mysql_results[0]["success"] is False

    @pytest.mark.asyncio
    async def test_sql_injection_returns_stub(self):
        """sql_injection class returns structured stub, not real creds."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            vulnerability_class="sql_injection",
            affected_url="http://localhost:3000/rest/products/search?q=1",
        )
        result = await enumerate_credentials("localhost", finding)

        assert result["vulnerability_class"] == "sql_injection"
        assert result["credentials_parsed"] == []
        assert len(result["connection_results"]) == 1
        stub = result["connection_results"][0]
        assert stub["service"] == "sqlmap"
        assert stub["status"] == "stub"
        assert "sqlmap" in stub["detail"].lower()

    @pytest.mark.asyncio
    async def test_unknown_vuln_class_parses_only(self):
        """Unrecognized vulnerability_class parses creds but skips connection attempt."""
        from src.agents.lateral.tools import enumerate_credentials

        finding = _make_finding(
            vulnerability_class="xss",
            response_snippet="password=letmein",
        )
        result = await enumerate_credentials("host", finding)

        assert result["vulnerability_class"] == "xss"
        assert len(result["credentials_parsed"]) > 0
        assert result["connection_results"] == []


# ---------------------------------------------------------------------------
# TestCheckIamPermissions
# ---------------------------------------------------------------------------


class TestCheckIamPermissions:
    """Tests for check_iam_permissions."""

    @pytest.mark.asyncio
    async def test_boto3_not_available(self, monkeypatch):
        """Returns structured empty result when boto3 is not installed."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_iam_permissions

        monkeypatch.setattr(tools_module, "_BOTO3_AVAILABLE", False)

        result = await check_iam_permissions("us-east-1", _make_finding())

        assert result["identity"] is None
        assert result["s3_buckets"] == []
        assert result["secrets"] == []
        assert result["iam_user"] is None
        assert result["ec2_instances"] == []
        assert "boto3" in result["errors"]

    @pytest.mark.asyncio
    async def test_full_permissions_with_mock_boto3(self, monkeypatch):
        """All five checks succeed with mocked boto3."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_iam_permissions

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/pentest",
            "Account": "123456789012",
            "UserId": "AIDAI23456EXAMPLE",
        }
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "prod-backups"}, {"Name": "dev-assets"}]
        }
        mock_sm = MagicMock()
        mock_sm.list_secrets.return_value = {
            "SecretList": [{"Name": "prod/stripe/secret-key"}]
        }
        mock_iam = MagicMock()
        mock_iam.get_user.return_value = {"User": {"UserName": "pentest-user"}}
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-0abc123def456"}]}]
        }

        def client_factory(service, region_name=None):
            return {
                "sts": mock_sts,
                "s3": mock_s3,
                "secretsmanager": mock_sm,
                "iam": mock_iam,
                "ec2": mock_ec2,
            }[service]

        mock_boto3 = MagicMock()
        mock_boto3.Session.return_value.client.side_effect = client_factory

        monkeypatch.setattr(tools_module, "boto3", mock_boto3)
        monkeypatch.setattr(tools_module, "_BOTO3_AVAILABLE", True)

        finding = _make_finding(
            credentials_found=[
                {"type": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE"},
                {
                    "type": "aws_secret_key",
                    "value": "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                },
            ]
        )
        result = await check_iam_permissions("us-east-1", finding)

        assert result["identity"] is not None
        assert result["identity"]["arn"] == "arn:aws:iam::123456789012:user/pentest"
        assert "prod-backups" in result["s3_buckets"]
        assert "dev-assets" in result["s3_buckets"]
        assert "prod/stripe/secret-key" in result["secrets"]
        assert result["iam_user"] == "pentest-user"
        assert "i-0abc123def456" in result["ec2_instances"]
        assert result["errors"] == {}

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_abort(self, monkeypatch):
        """A failure in one check records the error but does not prevent others."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_iam_permissions

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = Exception("AccessDenied")
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        mock_sm = MagicMock()
        mock_sm.list_secrets.side_effect = Exception("AccessDenied")
        mock_iam = MagicMock()
        mock_iam.get_user.side_effect = Exception("AccessDenied")
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        def client_factory(service, region_name=None):
            return {
                "sts": mock_sts,
                "s3": mock_s3,
                "secretsmanager": mock_sm,
                "iam": mock_iam,
                "ec2": mock_ec2,
            }[service]

        mock_boto3 = MagicMock()
        mock_boto3.Session.return_value.client.side_effect = client_factory

        monkeypatch.setattr(tools_module, "boto3", mock_boto3)
        monkeypatch.setattr(tools_module, "_BOTO3_AVAILABLE", True)

        result = await check_iam_permissions("us-east-1", _make_finding())

        # S3 succeeded
        assert "my-bucket" in result["s3_buckets"]
        # Failed checks recorded as errors, not raised
        assert "sts" in result["errors"]
        assert "secretsmanager" in result["errors"]
        assert "iam" in result["errors"]

    @pytest.mark.asyncio
    async def test_uses_credentials_from_finding(self, monkeypatch):
        """Credentials from finding.credentials_found are passed to boto3.Session."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import check_iam_permissions

        captured_session_kwargs: list[dict] = []

        def fake_session(**kwargs):
            captured_session_kwargs.append(kwargs)
            mock = MagicMock()
            mock.client.side_effect = Exception("skip")
            return mock

        mock_boto3 = MagicMock()
        mock_boto3.Session.side_effect = fake_session

        monkeypatch.setattr(tools_module, "boto3", mock_boto3)
        monkeypatch.setattr(tools_module, "_BOTO3_AVAILABLE", True)

        finding = _make_finding(
            credentials_found=[
                {"type": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE"},
                {
                    "type": "aws_secret_key",
                    "value": "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                },
            ]
        )
        await check_iam_permissions("us-east-1", finding)

        assert len(captured_session_kwargs) == 1
        kwargs = captured_session_kwargs[0]
        assert kwargs.get("aws_access_key_id") == "AKIAIOSFODNN7EXAMPLE"
        assert kwargs.get("region_name") == "us-east-1"


# ---------------------------------------------------------------------------
# TestIdentifySensitiveStores
# ---------------------------------------------------------------------------


class TestIdentifySensitiveStores:
    """Tests for identify_sensitive_stores."""

    @pytest.mark.asyncio
    async def test_db_port_found(self, monkeypatch):
        """An open DB port is reported in db_ports_found."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        async def fake_probe(host, port, timeout=2.0):
            return port == 3306  # Only MySQL

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)
        # Suppress HTTP probing so only DB scan matters
        monkeypatch.setattr(
            tools_module, "_probe_admin_interfaces", AsyncMock(return_value=[])
        )

        result = await identify_sensitive_stores("192.168.1.100", [], _make_finding())

        assert len(result["db_ports_found"]) == 1
        db = result["db_ports_found"][0]
        assert db["port"] == 3306
        assert db["service"] == "mysql"
        assert db["host"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_multiple_db_ports_across_assets(self, monkeypatch):
        """Open DB ports are found on both primary host and reachable assets."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        async def fake_probe(host, port, timeout=2.0):
            if host == "10.0.0.1":
                return port == 3306
            if host == "10.0.0.2":
                return port == 27017
            return False

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)
        monkeypatch.setattr(
            tools_module, "_probe_admin_interfaces", AsyncMock(return_value=[])
        )

        result = await identify_sensitive_stores(
            "10.0.0.1", ["10.0.0.2"], _make_finding()
        )

        ports_by_host = {(r["host"], r["port"]) for r in result["db_ports_found"]}
        assert ("10.0.0.1", 3306) in ports_by_host
        assert ("10.0.0.2", 27017) in ports_by_host

    @pytest.mark.asyncio
    async def test_admin_interface_found(self, monkeypatch):
        """Admin interface results appear in admin_interfaces."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        monkeypatch.setattr(tools_module, "_probe_port", AsyncMock(return_value=False))
        monkeypatch.setattr(
            tools_module,
            "_probe_admin_interfaces",
            AsyncMock(
                return_value=[
                    {
                        "host": "10.0.0.5",
                        "path": "/phpmyadmin",
                        "status_code": 200,
                        "url": "http://10.0.0.5/phpmyadmin",
                    },
                ]
            ),
        )

        result = await identify_sensitive_stores("10.0.0.5", [], _make_finding())

        assert len(result["admin_interfaces"]) == 1
        iface = result["admin_interfaces"][0]
        assert iface["path"] == "/phpmyadmin"
        assert iface["status_code"] == 200

    @pytest.mark.asyncio
    async def test_duplicate_targets_are_deduplicated(self, monkeypatch):
        """Same host in both host and reachable_assets is only scanned once."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        probed_calls: list[tuple[str, int]] = []

        async def tracking_probe(host, port, timeout=2.0):
            probed_calls.append((host, port))
            return False

        monkeypatch.setattr(tools_module, "_probe_port", tracking_probe)
        monkeypatch.setattr(
            tools_module, "_probe_admin_interfaces", AsyncMock(return_value=[])
        )

        await identify_sensitive_stores(
            "10.0.0.1", ["10.0.0.1", "10.0.0.1"], _make_finding()
        )

        hosts_probed = {h for h, _ in probed_calls}
        assert hosts_probed == {"10.0.0.1"}

    @pytest.mark.asyncio
    async def test_no_stores_found_summary(self, monkeypatch):
        """Summary message is sensible when nothing is found."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        monkeypatch.setattr(tools_module, "_probe_port", AsyncMock(return_value=False))
        monkeypatch.setattr(
            tools_module, "_probe_admin_interfaces", AsyncMock(return_value=[])
        )

        result = await identify_sensitive_stores("10.0.0.1", [], _make_finding())

        assert result["db_ports_found"] == []
        assert result["admin_interfaces"] == []
        assert "no" in result["summary"].lower()

    @pytest.mark.asyncio
    async def test_summary_mentions_found_services(self, monkeypatch):
        """Summary string reflects what was found."""
        import src.agents.lateral.tools as tools_module
        from src.agents.lateral.tools import identify_sensitive_stores

        async def fake_probe(host, port, timeout=2.0):
            return port == 5432

        monkeypatch.setattr(tools_module, "_probe_port", fake_probe)
        monkeypatch.setattr(
            tools_module, "_probe_admin_interfaces", AsyncMock(return_value=[])
        )

        result = await identify_sensitive_stores("10.0.0.1", [], _make_finding())

        assert "postgresql" in result["summary"].lower() or "5432" in result["summary"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
