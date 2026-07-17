"""Core data models shared across scanners, state, and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FindingStatus(str, Enum):
    """Lifecycle of a flagged resource."""

    NEW = "new"                        # just found by scan, not yet reviewed
    APPROVED = "approved"              # human approved; not yet tagged in AWS
    PENDING_DELETION = "pending"       # tagged in AWS, grace period counting down
    DECLINED = "declined"              # human declined; won't be re-prompted
    DELETED = "deleted"                # swept and removed
    SKIPPED_PROTECTED = "protected"    # excluded via ignore tag/pattern, never prompted


@dataclass
class ResourceRef:
    """Identifies a single AWS resource."""

    resource_type: str      # e.g. "ebs_volume", "elastic_ip"
    resource_id: str        # e.g. "vol-0123456789abcdef0"
    region: str
    account_id: str | None = None
    name: str | None = None  # from Name tag, if present

    @property
    def key(self) -> str:
        """Stable identity used for state tracking, independent of account_id
        (which may be unknown until first AWS call resolves it)."""
        return f"{self.resource_type}:{self.region}:{self.resource_id}"


@dataclass
class Finding:
    """A single scanner's verdict that a resource looks unused."""

    resource: ResourceRef
    reason: str                       # short human label, e.g. "unattached"
    evidence: str                     # detail, e.g. "unattached since 2026-06-01 (32 days)"
    estimated_monthly_cost_usd: float | None = None
    status: FindingStatus = FindingStatus.NEW
    scanned_at: datetime = field(default_factory=utcnow)
    pending_deletion_at: datetime | None = None   # grace period expiry, once tagged
    reviewed_at: datetime | None = None
    deleted_at: datetime | None = None
    extra: dict = field(default_factory=dict)     # scanner-specific metadata

    @property
    def key(self) -> str:
        return self.resource.key


@dataclass
class ScanResult:
    """Aggregate output of one `scan` invocation."""

    findings: list[Finding]
    regions_scanned: list[str]
    scanners_run: list[str]
    started_at: datetime
    finished_at: datetime
    errors: list[str] = field(default_factory=list)
