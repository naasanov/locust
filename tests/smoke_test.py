"""
Smoke tests for REC-01 environment setup.

Run with: pytest tests/smoke_test.py -v
"""

import pytest
from importlib.util import find_spec


class TestDependencies:
    """Verify all required dependencies are installed."""

    def test_google_genai_import(self):
        """Test google-genai is installed."""
        assert find_spec("google.genai") is not None, (
            "google-genai is missing. Install with: pip install google-genai"
        )

    def test_python_nmap_import(self):
        """Test python-nmap is installed."""
        import nmap
        assert nmap is not None

    def test_httpx_import(self):
        """Test httpx is installed."""
        import httpx
        assert httpx is not None

    def test_dotenv_import(self):
        """Test python-dotenv is installed."""
        from dotenv import load_dotenv
        assert load_dotenv is not None

    def test_motor_import(self):
        """Test motor (async MongoDB) is installed."""
        import motor.motor_asyncio
        assert motor.motor_asyncio is not None

    def test_shodan_import(self):
        """Test shodan is installed."""
        import shodan
        assert shodan is not None

    def test_pydantic_import(self):
        """Test pydantic is installed."""
        from pydantic import BaseModel
        assert BaseModel is not None


class TestModuleStructure:
    """Verify module structure is correct."""

    def test_recon_agent_import(self):
        """Test src.agents.recon package imports."""
        from src.agents.recon import ReconAgent
        assert ReconAgent is not None

    def test_tools_import(self):
        """Test all tools are importable."""
        from src.agents.recon.tools import (
            run_nmap,
            enumerate_subdomains,
            crawl_endpoints,
            check_exposed_files,
            shodan_lookup,
        )
        assert run_nmap is not None
        assert enumerate_subdomains is not None
        assert crawl_endpoints is not None
        assert check_exposed_files is not None
        assert shodan_lookup is not None

    def test_models_import(self):
        """Test models are importable."""
        from src.models.asset import AssetDocument, ServiceInfo, ExposedFile
        from src.models.scope import ScopeDocument

        assert AssetDocument is not None
        assert ServiceInfo is not None
        assert ExposedFile is not None
        assert ScopeDocument is not None

    def test_scoring_import(self):
        """Test scoring module is importable."""
        from src.agents.recon.scoring import GeminiScorer
        assert GeminiScorer is not None

    def test_config_import(self):
        """Test config is importable."""
        from src.config import Settings, get_settings
        assert Settings is not None
        assert get_settings is not None

    def test_db_import(self):
        """Test db module is importable."""
        from src.db.mongo import get_db
        assert get_db is not None


class TestAssetModel:
    """Test AssetDocument model functionality."""

    def test_create_asset(self):
        """Test creating a basic asset."""
        from src.models.asset import AssetDocument

        asset = AssetDocument(
            engagement_id="test-123",
            asset_type="host",
            ip="192.168.1.1",
            attack_surface_score=0.5,
        )

        assert asset.engagement_id == "test-123"
        assert asset.asset_type == "host"
        assert asset.ip == "192.168.1.1"
        assert asset.attack_surface_score == 0.5

    def test_asset_defaults(self):
        """Test asset default values."""
        from src.models.asset import AssetDocument

        asset = AssetDocument(
            engagement_id="test-123",
            asset_type="web_app",
            url="https://example.com",
        )

        assert asset.open_ports == []
        assert asset.services == []
        assert asset.endpoints == []
        assert asset.exposed_files == []
        assert asset.shodan_vulns == []
        assert asset.attack_surface_score == 0.0

    def test_asset_with_services(self):
        """Test asset with services."""
        from src.models.asset import AssetDocument, ServiceInfo

        asset = AssetDocument(
            engagement_id="test-123",
            asset_type="web_app",
            url="https://example.com",
            open_ports=[80, 443],
            services=[ServiceInfo(port=443, service="nginx", version="1.24")],
            attack_surface_score=0.7,
        )

        assert asset.open_ports == [80, 443]
        assert len(asset.services) == 1
        assert asset.services[0].service == "nginx"

    def test_asset_score_validation(self):
        """Test that score must be between 0 and 1."""
        from src.models.asset import AssetDocument
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AssetDocument(
                engagement_id="test-123",
                asset_type="host",
                ip="192.168.1.1",
                attack_surface_score=1.5,  # Invalid
            )

    def test_asset_serialization(self):
        """Test asset serialization with model_dump."""
        from src.models.asset import AssetDocument

        asset = AssetDocument(
            engagement_id="test-123",
            asset_type="host",
            ip="192.168.1.1",
        )

        data = asset.model_dump(mode="json")
        assert data["engagement_id"] == "test-123"
        assert data["asset_type"] == "host"
        assert data["ip"] == "192.168.1.1"


class TestScopeModel:
    """Test ScopeDocument model functionality."""

    def test_create_scope(self):
        """Test creating scope document."""
        from datetime import datetime, timezone
        from src.models.scope import (
            ScopeDocument, Targets, ForbiddenSpec,
            EngagementConstraints, ActiveHours, ActiveWindow
        )

        scope = ScopeDocument(
            engagement_id="abc123",
            customer="Acme Corp",
            targets=Targets(
                domains=["acmecorp.com", "*.acmecorp.com"],
                ip_ranges=["203.0.113.0/24"],
            ),
            forbidden_spec=ForbiddenSpec(
                forbidden_hosts=["payments.acmecorp.com"],
                forbidden_actions=["destructive_payloads"],
            ),
            constraints=EngagementConstraints(
                active_hours=ActiveHours(
                    timezone="UTC",
                    windows=[ActiveWindow(days=["mon"], start="22:00", end="06:00")],
                ),
                expires_at=datetime(2026, 12, 31, tzinfo=timezone.utc),
            ),
        )

        assert scope.engagement_id == "abc123"
        assert scope.customer == "Acme Corp"
        assert "acmecorp.com" in scope.targets.domains

    def test_scope_forbidden_hosts(self):
        """Test forbidden hosts checking."""
        from src.models.scope import ForbiddenSpec

        forbidden = ForbiddenSpec(
            forbidden_hosts=["payments.acmecorp.com", "10.0.1.50"],
        )

        assert "payments.acmecorp.com" in forbidden.forbidden_hosts
        assert "api.acmecorp.com" not in forbidden.forbidden_hosts


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
