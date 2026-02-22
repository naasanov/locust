from unittest.mock import patch

from src.agents.exploit import ExploitAgent
from src.agents.lateral import LateralAgent
from src.agents.mock_agents import MockExploitAgent, MockLateralAgent, MockReconAgent
from src.agents.recon import ReconAgent
from src.config import get_settings
from src.container import build_orchestrator


def test_build_orchestrator_uses_mock_modes(monkeypatch):
    monkeypatch.setenv("AGENT_RECON_MODE", "mock")
    monkeypatch.setenv("AGENT_EXPLOIT_MODE", "real")
    monkeypatch.setenv("AGENT_LATERAL_MODE", "mock")
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-key")
    get_settings.cache_clear()

    with patch("src.container.get_db", return_value=object()):
        orchestrator = build_orchestrator(broadcast=None)

    assert isinstance(orchestrator.recon, MockReconAgent)
    assert isinstance(orchestrator.exploit, ExploitAgent)
    assert isinstance(orchestrator.lateral, MockLateralAgent)


def test_build_orchestrator_uses_real_modes(monkeypatch):
    monkeypatch.setenv("AGENT_RECON_MODE", "real")
    monkeypatch.setenv("AGENT_EXPLOIT_MODE", "real")
    monkeypatch.setenv("AGENT_LATERAL_MODE", "real")
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-key")
    get_settings.cache_clear()

    with patch("src.container.get_db", return_value=object()):
        orchestrator = build_orchestrator(broadcast=None)

    assert isinstance(orchestrator.recon, ReconAgent)
    assert isinstance(orchestrator.exploit, ExploitAgent)
    assert isinstance(orchestrator.lateral, LateralAgent)
