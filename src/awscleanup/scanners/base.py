"""Scanner protocol: every resource-type scanner implements this interface.

A scanner's `detect()` must be strictly read-only. `tag()` and `delete()`
are the only methods allowed to mutate AWS, and are only ever called by
`review` (tag) and `sweep` (delete) after explicit human confirmation.
"""

from __future__ import annotations

from typing import Protocol

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef


class Scanner(Protocol):
    resource_type: str  # e.g. "ebs_volume" — must match ResourceRef.resource_type

    def detect(
        self, session: boto3.Session, region: str, settings: Settings
    ) -> list[Finding]:
        """Read-only: return findings for unused resources of this type in `region`."""
        ...

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        """Re-verify at sweep time. Returns (still_unused, detail). Must be
        called again right before delete() to avoid deleting a resource that
        became in-use after being tagged."""
        ...

    def tag_pending_deletion(
        self, session: boto3.Session, resource: ResourceRef, tags: dict[str, str]
    ) -> None:
        """Apply the pending-deletion + reason tags to the live resource."""
        ...

    def untag_pending_deletion(self, session: boto3.Session, resource: ResourceRef) -> None:
        """Remove the pending-deletion tags (used when a resource is
        reconsidered/declined after having been tagged)."""
        ...

    def delete(self, session: boto3.Session, resource: ResourceRef) -> None:
        """Actually delete the resource. Only called by `sweep`."""
        ...


_REGISTRY: dict[str, Scanner] = {}


def register(scanner: Scanner) -> Scanner:
    _REGISTRY[scanner.resource_type] = scanner
    return scanner


def all_scanners() -> list[Scanner]:
    # Import here (not at module load) so registration side-effects run
    # exactly once, on first use, regardless of import order.
    from awscleanup.scanners import (  # noqa: F401
        ebs_snapshots,
        ebs_volumes,
        ec2_instances,
        elastic_ips,
        load_balancers,
        security_groups,
    )

    return list(_REGISTRY.values())


def get_scanner(resource_type: str) -> Scanner:
    all_scanners()  # ensure registry populated
    return _REGISTRY[resource_type]
