import asyncio
from src.container import build_orchestrator
from src.models.scope import ScopeDocument

async def main():
    orchestrator = build_orchestrator(broadcast=broadcast)  # pass your ws_manager broadcast fn
    scope = ScopeDocument(engagement_id=settings.ENGAGEMENT_ID, target_url=settings.TARGET_URL)
    
    while True:
        await orchestrator.run_cycle(scope)
        await asyncio.sleep(60)  # short for demo