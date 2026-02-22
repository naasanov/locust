import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, model_validator

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
    open_ports: list[int] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)  # e.g. ["nginx/1.24.0", "node.js", "react", "postgresql"]
    endpoints: list[str] = Field(default_factory=list)
    exposed_files: list[ExposedFile] = Field(default_factory=list)
    # Kept for schema compatibility with downstream consumers.
    shodan_vulns: list[str] = Field(default_factory=list)
    secrets_found: list[SecretFound] = Field(default_factory=list)
    cloud_issues: list[CloudIssue] = Field(default_factory=list)
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=1.0)
    score_reasoning: str | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def _validate_locator(self) -> "AssetDocument":
        # Every asset must be locatable by at least one identifier.
        if not self.ip and not self.url:
            raise ValueError("AssetDocument requires at least one of 'ip' or 'url'")
        return self

    def to_recon_output(self) -> dict:
        """
        Canonical recon payload shape shared with downstream consumers.

        This intentionally mirrors the agreed schema ordering for readability.
        """
        return {
            "engagement_id": self.engagement_id,
            "asset_type": self.asset_type,
            "url": self.url,
            "ip": self.ip,
            "open_ports": self.open_ports,
            "services": [service.model_dump(mode="json") for service in self.services],
            "tech_stack": self.tech_stack,
            "endpoints": self.endpoints,
            "secrets_found": [secret.model_dump(mode="json") for secret in self.secrets_found],
            "cloud_issues": [issue.model_dump(mode="json") for issue in self.cloud_issues],
            "attack_surface_score": self.attack_surface_score,
            "score_reasoning": self.score_reasoning,
            "discovered_at": self.discovered_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
