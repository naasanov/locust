"""
Agent contracts. Any class with a matching async run() signature satisfies the protocol —
no inheritance required. Swap implementations in container.py.
"""
from typing import Protocol, runtime_checkable

from src.models.asset import AssetDocument
from src.models.attack_chain import AttackChain
from src.models.finding import FindingDocument, LateralAgentInput
from src.models.scope import ScopeDocument


@runtime_checkable
class ReconProtocol(Protocol):
    async def run(self, scope: ScopeDocument) -> list[AssetDocument]:
        ...


@runtime_checkable
class ExploitProtocol(Protocol):
    async def run(self, assets: list[AssetDocument]) -> list[FindingDocument]:
        ...


@runtime_checkable
class LateralProtocol(Protocol):
    async def run(self, input: LateralAgentInput) -> list[AttackChain]:
        ...
