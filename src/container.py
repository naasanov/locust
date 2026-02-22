"""
Composition root — the only file you need to touch to swap agent implementations.

To replace an agent:
  1. Implement a class with a matching async run() signature (see agents/protocols.py).
  2. Import it here and pass it to Orchestrator instead of the stub.
  3. Nothing else changes.
"""
from src.agents.exploit import ExploitAgent
from src.agents.lateral import LateralAgent
from src.agents.recon import ReconAgent
from src.config import get_settings
from src.db.mongo import get_db
from src.orchestrator import BroadcastFn, Orchestrator


def build_orchestrator(broadcast: BroadcastFn | None = None) -> Orchestrator:
    settings = get_settings()
    return Orchestrator(
        recon=ReconAgent(),
        exploit=ExploitAgent(gemini_api_key=settings.GEMINI_API_KEY or None),
        lateral=LateralAgent(),
        db=get_db(),
        broadcast=broadcast,
    )
