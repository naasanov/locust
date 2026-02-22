"""Asset model for Recon Agent output."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class AssetType(str, Enum):
    HOST = "host"
    WEB_APP = "web_app"
    SUBDOMAIN = "subdomain"


@dataclass
class Service:
    """Service discovered on a port."""
    port: int
    service: str
    version: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "version": self.version,
        }


@dataclass
class ExposedFile:
    """Exposed sensitive file discovered."""
    path: str
    size: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
        }


@dataclass
class AssetMetadata:
    """Internal metadata for asset tracking."""
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    recon_cycle: int = 1
    tool_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "discovered_at": self.discovered_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "recon_cycle": self.recon_cycle,
            "tool_sources": self.tool_sources,
        }


@dataclass
class Asset:
    """
    Asset discovered by the Recon Agent.

    Schema version: 1.0.0
    See docs/schemas/asset_schema.md for full documentation.
    """
    engagement_id: str
    asset_type: AssetType
    attack_surface_score: float = 0.0

    # Network identifiers (at least one must be set)
    ip: Optional[str] = None
    url: Optional[str] = None

    # Discovery data
    open_ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    exposed_files: list[ExposedFile] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)

    # Metadata
    _metadata: AssetMetadata = field(default_factory=AssetMetadata)

    def __post_init__(self):
        if self.ip is None and self.url is None:
            raise ValueError("At least one of ip or url must be set")
        if not 0.0 <= self.attack_surface_score <= 1.0:
            raise ValueError("attack_surface_score must be between 0.0 and 1.0")

    def to_dict(self) -> dict:
        """Convert to MongoDB-ready dictionary."""
        return {
            "engagement_id": self.engagement_id,
            "asset_type": self.asset_type.value,
            "ip": self.ip,
            "url": self.url,
            "open_ports": self.open_ports,
            "services": [s.to_dict() for s in self.services],
            "endpoints": self.endpoints,
            "exposed_files": [f.to_dict() for f in self.exposed_files],
            "shodan_vulns": self.shodan_vulns,
            "attack_surface_score": self.attack_surface_score,
            "_metadata": self._metadata.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Asset":
        """Create Asset from MongoDB document."""
        metadata_data = data.get("_metadata", {})
        metadata = AssetMetadata(
            discovered_at=datetime.fromisoformat(metadata_data.get("discovered_at", datetime.utcnow().isoformat())),
            last_seen=datetime.fromisoformat(metadata_data.get("last_seen", datetime.utcnow().isoformat())),
            recon_cycle=metadata_data.get("recon_cycle", 1),
            tool_sources=metadata_data.get("tool_sources", []),
        )

        return cls(
            engagement_id=data["engagement_id"],
            asset_type=AssetType(data["asset_type"]),
            ip=data.get("ip"),
            url=data.get("url"),
            open_ports=data.get("open_ports", []),
            services=[Service(**s) for s in data.get("services", [])],
            endpoints=data.get("endpoints", []),
            exposed_files=[ExposedFile(**f) for f in data.get("exposed_files", [])],
            shodan_vulns=data.get("shodan_vulns", []),
            attack_surface_score=data.get("attack_surface_score", 0.0),
            _metadata=metadata,
        )

    def add_tool_source(self, tool_name: str) -> None:
        """Record which tool contributed to this asset."""
        if tool_name not in self._metadata.tool_sources:
            self._metadata.tool_sources.append(tool_name)
        self._metadata.last_seen = datetime.utcnow()
