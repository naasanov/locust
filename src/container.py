"""
Composition root — the only file you need to touch to swap agent implementations.

To replace an agent:
  1. Implement a class with a matching async run() signature (see agents/protocols.py).
  2. Import it here and pass it to Orchestrator instead of the stub.
  3. Nothing else changes.
"""
import logging

from src.agents.exploit import ExploitAgent
from src.agents.lateral import LateralAgent
from src.agents.mock_agents import MockExploitAgent, MockLateralAgent, MockReconAgent
from src.agents.recon import ReconAgent
from src.config import get_settings
from src.db.mongo import get_db
from src.orchestrator import BroadcastFn, Orchestrator

logger = logging.getLogger(__name__)


def _use_mock(mode: str) -> bool:
    return mode.strip().lower() == "mock"


def build_orchestrator(broadcast: BroadcastFn | None = None) -> Orchestrator:
    settings = get_settings()
    recon_mode = settings.AGENT_RECON_MODE
    exploit_mode = settings.AGENT_EXPLOIT_MODE
    lateral_mode = settings.AGENT_LATERAL_MODE

    recon = (
        MockReconAgent(event_emitter=broadcast)
        if _use_mock(recon_mode)
        else ReconAgent(
            gemini_api_key=settings.GEMINI_API_KEY or None,
            censys_api_key=settings.CENSYS_API_KEY or None,
            github_token=settings.GITHUB_TOKEN or None,
            event_emitter=broadcast,
        )
    )
    exploit = (
        MockExploitAgent(event_emitter=broadcast)
        if _use_mock(exploit_mode)
        else ExploitAgent(
            gemini_api_key=settings.GEMINI_API_KEY or None,
            event_emitter=broadcast,
        )
    )
    lateral = (
        MockLateralAgent(event_emitter=broadcast)
        if _use_mock(lateral_mode)
        else LateralAgent(event_emitter=broadcast)
    )
    logger.info(
        "Agent modes selected: recon=%s exploit=%s lateral=%s",
        recon_mode,
        exploit_mode,
        lateral_mode,
    )

    return Orchestrator(
        recon=recon,
        exploit=exploit,
        lateral=lateral,
        db=get_db(),
        broadcast=broadcast,
    )
