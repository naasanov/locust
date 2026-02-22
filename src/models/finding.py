from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from src.models.asset import AssetDocument

Severity = Literal["critical", "high", "medium", "low", "info"]
BlastRadius = Literal["single_asset", "multi_asset"]


class Evidence(BaseModel):
    request: str
    response_snippet: str
    status_code: int


class CredentialFound(BaseModel):
    type: str    # e.g. "database", "aws_secret"
    value: str   # may be redacted


class FindingDocument(BaseModel):
    engagement_id: str
    asset_id: str
    finding_id: str
    vulnerability_class: str
    title: str
    severity: Severity
    exploitable: bool
    affected_url: str
    evidence: Evidence
    credentials_found: list[CredentialFound] = []
    gemini_reasoning: str | None = None
    blast_radius: BlastRadius
    on_chain_tx: str | None = None
    remediation: str | None = None
    mitre_technique: str | None = None  # e.g. "T1552.001"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LateralAgentInput(BaseModel):
    """Combined input for the Lateral Movement Agent."""
    findings: list[FindingDocument]
    asset_graph: list[AssetDocument]
