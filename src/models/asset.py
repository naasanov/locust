import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

AssetType = Literal["host", "web_app", "subdomain"]


class ServiceInfo(BaseModel):
    port: int
    service: str
    version: str | None = None


class ExposedFile(BaseModel):
    path: str
    size: int | None = None  # bytes


class SecretFound(BaseModel):
    source: str          # e.g. "github"
    type: str            # e.g. "aws_access_key"
    value: str           # redacted or raw
    repo: str | None = None
    commit: str | None = None


class CloudIssue(BaseModel):
    type: str            # e.g. "s3_bucket_public"
    resource: str


class AssetDocument(BaseModel):
    asset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    asset_type: AssetType
    ip: str | None = None
    url: str | None = None
    open_ports: list[int] = []
    services: list[ServiceInfo] = []
    endpoints: list[str] = []
    exposed_files: list[ExposedFile] = []
    shodan_vulns: list[str] = []
    secrets_found: list[SecretFound] = []
    cloud_issues: list[CloudIssue] = []
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=1.0)
    score_reasoning: str | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
