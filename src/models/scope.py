from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class CloudAccount(BaseModel):
    provider: Literal["aws", "gcp", "azure"]
    account_id: str | None = None  # AWS
    project_id: str | None = None  # GCP


class Targets(BaseModel):
    domains: list[str] = []
    ip_ranges: list[str] = []
    cloud_accounts: list[CloudAccount] = []


class ActiveWindow(BaseModel):
    days: list[str]
    start: str  # HH:MM
    end: str    # HH:MM


class ActiveHours(BaseModel):
    timezone: str
    windows: list[ActiveWindow]


class ForbiddenSpec(BaseModel):
    forbidden_hosts: list[str] = []
    forbidden_actions: list[str] = []
    tier_limit: int = 2


class EngagementConstraints(BaseModel):
    active_hours: ActiveHours
    cycle_interval_hours: int = 24
    expires_at: datetime
    monthly_fee_usdc: float = 0.0


class ScopeDocument(BaseModel):
    engagement_id: str
    customer: str
    targets: Targets
    forbidden_spec: ForbiddenSpec
    constraints: EngagementConstraints
    github_repo_url: str | None = None  # optional: e.g. "https://github.com/org/repo"
