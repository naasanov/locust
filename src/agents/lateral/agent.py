from src.models.attack_chain import AttackChain
from src.models.finding import LateralAgentInput


class LateralAgent:
    """
    Fully agentic: Gemini Pro reasons across the confirmed finding + full asset graph
    and decides pivot paths via tool calls (up to 8 rounds per finding).

    Implement run() and replace this stub.
    """

    async def run(self, input: LateralAgentInput) -> list[AttackChain]:
        raise NotImplementedError
