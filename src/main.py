import asyncio
from src.config import get_settings
from src.container import build_orchestrator
from src.models.scope import ScopeDocument

async def main():
    settings = get_settings()
    orchestrator = build_orchestrator(broadcast=None)
    scope = ScopeDocument(engagement_id=settings.ENGAGEMENT_ID, target_url=settings.TARGET_URL)
    
    while True:
        await orchestrator.run_cycle(scope)
        await asyncio.sleep(60)  # short for demo