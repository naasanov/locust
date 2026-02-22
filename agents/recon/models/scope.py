"""Scope document models for engagement configuration."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CloudAccount:
    """Cloud account in scope."""
    provider: str  # aws, gcp, azure
    account_id: Optional[str] = None  # AWS account ID
    project_id: Optional[str] = None  # GCP project ID

    def to_dict(self) -> dict:
        result = {"provider": self.provider}
        if self.account_id:
            result["account_id"] = self.account_id
        if self.project_id:
            result["project_id"] = self.project_id
        return result


@dataclass
class ActiveWindow:
    """Time window when recon is allowed."""
    days: list[str]  # mon, tue, wed, thu, fri, sat, sun
    start: str  # HH:MM format
    end: str  # HH:MM format

    def to_dict(self) -> dict:
        return {
            "days": self.days,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class ScopeTargets:
    """Targets in scope for the engagement."""
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    cloud_accounts: list[CloudAccount] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domains": self.domains,
            "ip_ranges": self.ip_ranges,
            "cloud_accounts": [c.to_dict() for c in self.cloud_accounts],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeTargets":
        return cls(
            domains=data.get("domains", []),
            ip_ranges=data.get("ip_ranges", []),
            cloud_accounts=[
                CloudAccount(**c) for c in data.get("cloud_accounts", [])
            ],
        )


@dataclass
class ForbiddenActions:
    """Actions and hosts that are out of scope."""
    forbidden_hosts: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    tier_limit: int = 2  # Max exploitation tier

    def to_dict(self) -> dict:
        return {
            "forbidden_hosts": self.forbidden_hosts,
            "forbidden_actions": self.forbidden_actions,
            "tier_limit": self.tier_limit,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ForbiddenActions":
        return cls(
            forbidden_hosts=data.get("forbidden_hosts", []),
            forbidden_actions=data.get("forbidden_actions", []),
            tier_limit=data.get("tier_limit", 2),
        )

    def is_host_forbidden(self, host: str) -> bool:
        """Check if a host is in the forbidden list."""
        return host in self.forbidden_hosts

    def is_action_forbidden(self, action: str) -> bool:
        """Check if an action is forbidden."""
        return action in self.forbidden_actions


@dataclass
class EngagementConstraints:
    """Operational constraints for the engagement."""
    timezone: str = "UTC"
    windows: list[ActiveWindow] = field(default_factory=list)
    cycle_interval_hours: int = 24
    expires_at: Optional[datetime] = None
    monthly_fee_usdc: float = 0.0

    def to_dict(self) -> dict:
        return {
            "active_hours": {
                "timezone": self.timezone,
                "windows": [w.to_dict() for w in self.windows],
            },
            "cycle_interval_hours": self.cycle_interval_hours,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "monthly_fee_usdc": self.monthly_fee_usdc,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EngagementConstraints":
        active_hours = data.get("active_hours", {})
        windows_data = active_hours.get("windows", [])
        expires_at = data.get("expires_at")

        return cls(
            timezone=active_hours.get("timezone", "UTC"),
            windows=[ActiveWindow(**w) for w in windows_data],
            cycle_interval_hours=data.get("cycle_interval_hours", 24),
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            monthly_fee_usdc=data.get("monthly_fee_usdc", 0.0),
        )

    def is_expired(self) -> bool:
        """Check if the engagement has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


@dataclass
class Scope:
    """
    Complete scope document for an engagement.

    Loaded from MongoDB and verified against on-chain hash
    before every recon cycle.
    """
    engagement_id: str
    customer: str
    targets: ScopeTargets
    forbidden: ForbiddenActions
    constraints: EngagementConstraints

    # Hash verification
    document_hash: Optional[str] = None  # SHA-256 of the document

    def to_dict(self) -> dict:
        """Convert to MongoDB document format."""
        return {
            "engagement_id": self.engagement_id,
            "customer": self.customer,
            "targets": self.targets.to_dict(),
            "forbidden_hosts": self.forbidden.forbidden_hosts,
            "forbidden_actions": self.forbidden.forbidden_actions,
            "tier_limit": self.forbidden.tier_limit,
            **self.constraints.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        """Create Scope from MongoDB document."""
        # Extract targets
        targets_data = data.get("targets", {})
        targets = ScopeTargets.from_dict(targets_data)

        # Extract forbidden actions
        forbidden = ForbiddenActions(
            forbidden_hosts=data.get("forbidden_hosts", []),
            forbidden_actions=data.get("forbidden_actions", []),
            tier_limit=data.get("tier_limit", 2),
        )

        # Extract constraints
        constraints = EngagementConstraints.from_dict(data)

        return cls(
            engagement_id=data["engagement_id"],
            customer=data.get("customer", "Unknown"),
            targets=targets,
            forbidden=forbidden,
            constraints=constraints,
        )

    def is_target_in_scope(self, target: str) -> bool:
        """Check if a target (domain, IP, subdomain) is in scope."""
        # Check forbidden first
        if self.forbidden.is_host_forbidden(target):
            return False

        # Check domains (including wildcards)
        for domain in self.targets.domains:
            if domain.startswith("*."):
                # Wildcard domain
                base = domain[2:]
                if target.endswith(base) or target == base:
                    return True
            elif target == domain:
                return True

        # Check IP ranges (simplified - would need proper CIDR handling)
        for ip_range in self.targets.ip_ranges:
            if "/" in ip_range:
                # CIDR notation - simplified check
                network = ip_range.split("/")[0]
                if target.startswith(network.rsplit(".", 1)[0]):
                    return True
            elif target == ip_range:
                return True

        return False
