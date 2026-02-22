"""
Smoke tests for REC-01 environment setup.

Run with: pytest tests/smoke_test.py -v
"""

import pytest


class TestDependencies:
    """Verify all required dependencies are installed."""

    def test_google_generativeai_import(self):
        """Test google-generativeai is installed."""
        import google.generativeai as genai
        assert genai is not None

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

    def test_pymongo_import(self):
        """Test pymongo is installed."""
        import pymongo
        assert pymongo is not None

    def test_shodan_import(self):
        """Test shodan is installed."""
        import shodan
        assert shodan is not None


class TestModuleStructure:
    """Verify module structure is correct."""

    def test_agents_recon_import(self):
        """Test agents.recon package imports."""
        from agents.recon import ReconAgent
        assert ReconAgent is not None

    def test_tools_import(self):
        """Test all tools are importable."""
        from agents.recon.tools import (
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
        from agents.recon.models import Asset, Service, ExposedFile
        from agents.recon.models import Scope, ScopeTargets, ForbiddenActions

        assert Asset is not None
        assert Service is not None
        assert ExposedFile is not None
        assert Scope is not None

    def test_scoring_import(self):
        """Test scoring module is importable."""
        from agents.recon.scoring import GeminiScorer
        assert GeminiScorer is not None

    def test_config_import(self):
        """Test config is importable."""
        from config import Settings, get_settings
        assert Settings is not None
        assert get_settings is not None

    def test_db_import(self):
        """Test db module is importable."""
        from db import get_database, get_client
        assert get_database is not None
        assert get_client is not None


class TestAssetModel:
    """Test Asset model functionality."""

    def test_create_asset(self):
        """Test creating a basic asset."""
        from agents.recon.models import Asset, AssetType

        asset = Asset(
            engagement_id="test-123",
            asset_type=AssetType.HOST,
            ip="192.168.1.1",
            attack_surface_score=0.5,
        )

        assert asset.engagement_id == "test-123"
        assert asset.asset_type == AssetType.HOST
        assert asset.ip == "192.168.1.1"
        assert asset.attack_surface_score == 0.5

    def test_asset_requires_ip_or_url(self):
        """Test that asset requires at least ip or url."""
        from agents.recon.models import Asset, AssetType

        with pytest.raises(ValueError, match="At least one of ip or url"):
            Asset(
                engagement_id="test-123",
                asset_type=AssetType.HOST,
                # Neither ip nor url set
            )

    def test_asset_to_dict(self):
        """Test asset serialization."""
        from agents.recon.models import Asset, AssetType, Service

        asset = Asset(
            engagement_id="test-123",
            asset_type=AssetType.WEB_APP,
            url="https://example.com",
            open_ports=[80, 443],
            services=[Service(port=443, service="nginx", version="1.24")],
            attack_surface_score=0.7,
        )

        data = asset.to_dict()

        assert data["engagement_id"] == "test-123"
        assert data["asset_type"] == "web_app"
        assert data["url"] == "https://example.com"
        assert data["open_ports"] == [80, 443]
        assert len(data["services"]) == 1
        assert data["services"][0]["service"] == "nginx"

    def test_asset_score_validation(self):
        """Test that score must be between 0 and 1."""
        from agents.recon.models import Asset, AssetType

        with pytest.raises(ValueError, match="attack_surface_score must be between"):
            Asset(
                engagement_id="test-123",
                asset_type=AssetType.HOST,
                ip="192.168.1.1",
                attack_surface_score=1.5,  # Invalid
            )


class TestScopeModel:
    """Test Scope model functionality."""

    def test_create_scope_from_dict(self):
        """Test creating scope from dictionary."""
        from agents.recon.models import Scope

        data = {
            "engagement_id": "abc123",
            "customer": "Acme Corp",
            "targets": {
                "domains": ["acmecorp.com", "*.acmecorp.com"],
                "ip_ranges": ["203.0.113.0/24"],
                "cloud_accounts": [],
            },
            "forbidden_hosts": ["payments.acmecorp.com"],
            "forbidden_actions": ["destructive_payloads"],
            "tier_limit": 2,
            "active_hours": {
                "timezone": "America/New_York",
                "windows": [
                    {"days": ["mon", "tue"], "start": "22:00", "end": "06:00"}
                ],
            },
            "cycle_interval_hours": 24,
        }

        scope = Scope.from_dict(data)

        assert scope.engagement_id == "abc123"
        assert scope.customer == "Acme Corp"
        assert "acmecorp.com" in scope.targets.domains
        assert scope.forbidden.is_host_forbidden("payments.acmecorp.com")
        assert not scope.forbidden.is_host_forbidden("api.acmecorp.com")

    def test_scope_target_in_scope(self):
        """Test target scope checking."""
        from agents.recon.models import Scope

        data = {
            "engagement_id": "abc123",
            "customer": "Acme Corp",
            "targets": {
                "domains": ["acmecorp.com", "*.acmecorp.com"],
                "ip_ranges": ["203.0.113.10"],
                "cloud_accounts": [],
            },
            "forbidden_hosts": ["payments.acmecorp.com"],
            "forbidden_actions": [],
            "tier_limit": 2,
            "active_hours": {"timezone": "UTC", "windows": []},
        }

        scope = Scope.from_dict(data)

        # Should be in scope
        assert scope.is_target_in_scope("acmecorp.com")
        assert scope.is_target_in_scope("api.acmecorp.com")  # Wildcard match
        assert scope.is_target_in_scope("203.0.113.10")

        # Should be out of scope (forbidden)
        assert not scope.is_target_in_scope("payments.acmecorp.com")

        # Should be out of scope (not listed)
        assert not scope.is_target_in_scope("otherdomain.com")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
