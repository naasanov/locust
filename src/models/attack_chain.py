from datetime import datetime, timezone

from pydantic import BaseModel, Field


class PivotStep(BaseModel):
    step: int
    asset: str
    action: str
    detail: str
    mitre: str | None = None  # e.g. "T1552.001"


class SensitiveStore(BaseModel):
    type: str            # e.g. "database", "secret"
    asset: str
    contents: str
    credentials_used: str


class AttackChain(BaseModel):
    engagement_id: str
    chain_id: str
    entry_point_finding_id: str
    entry_point: str
    pivot_path: list[PivotStep]
    reachable_sensitive_stores: list[SensitiveStore] = []
    blast_radius_score: float = Field(0.0, ge=0.0, le=1.0)
    blast_radius_summary: str
    gemini_reasoning: str
    on_chain_tx: str | None = None
    mitre_techniques: list[str] = []
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
