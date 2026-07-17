"""Scanner: orphaned EBS snapshots (source volume no longer exists).

A manual snapshot whose source volume has since been deleted is still
billed for storage indefinitely. If the volume is gone, the snapshot's
original purpose (a restore point for that volume) is moot — though it may
still be a deliberate backup, so this is evidence, not a certainty; the
`cleanup:ignore` tag escape hatch matters most for this scanner.
"""

from __future__ import annotations

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef, utcnow
from awscleanup.scanners import base
from awscleanup.scanners.tags import dict_to_tag_spec, is_protected, resource_name, tags_to_dict

_PRICE_PER_GB_MONTH = 0.05


def _existing_volume_ids(ec2) -> set[str]:
    ids: set[str] = set()
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        ids.update(v["VolumeId"] for v in page["Volumes"])
    return ids


class EbsSnapshotScanner:
    resource_type = "ebs_snapshot"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        sts = session.client("sts", region_name=region)
        account_id = sts.get_caller_identity()["Account"]

        existing_volumes = _existing_volume_ids(ec2)
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page["Snapshots"]:
                volume_id = snap.get("VolumeId")
                if not volume_id or volume_id in existing_volumes:
                    continue  # source volume still exists (or snapshot has no volume ref)

                tags = tags_to_dict(snap.get("Tags"))
                if is_protected(tags, settings):
                    continue

                resource = ResourceRef(
                    resource_type=self.resource_type,
                    resource_id=snap["SnapshotId"],
                    region=region,
                    name=resource_name(tags),
                )
                age_days = (utcnow() - snap["StartTime"]).days
                size_gb = snap.get("VolumeSize", 0)

                findings.append(
                    Finding(
                        resource=resource,
                        reason="orphaned",
                        evidence=(
                            f"{size_gb}GiB snapshot, source volume {volume_id} no longer "
                            f"exists, taken {age_days}d ago"
                        ),
                        estimated_monthly_cost_usd=round(size_gb * _PRICE_PER_GB_MONTH, 2),
                        extra={"source_volume_id": volume_id, "size_gb": size_gb},
                    )
                )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        ec2 = session.client("ec2", region_name=resource.region)
        sts = session.client("sts", region_name=resource.region)
        account_id = sts.get_caller_identity()["Account"]
        try:
            resp = ec2.describe_snapshots(
                SnapshotIds=[resource.resource_id], OwnerIds=[account_id]
            )
        except ec2.exceptions.ClientError as e:
            if "InvalidSnapshot.NotFound" in str(e):
                return False, "snapshot no longer exists"
            raise
        snaps = resp["Snapshots"]
        if not snaps:
            return False, "snapshot no longer exists"

        volume_id = snaps[0].get("VolumeId")
        if volume_id and volume_id in _existing_volume_ids(ec2):
            return False, f"source volume {volume_id} exists again"
        return True, "source volume still missing"

    def tag_pending_deletion(
        self, session: boto3.Session, resource: ResourceRef, tags: dict[str, str]
    ) -> None:
        ec2 = session.client("ec2", region_name=resource.region)
        ec2.create_tags(Resources=[resource.resource_id], Tags=dict_to_tag_spec(tags))

    def untag_pending_deletion(self, session: boto3.Session, resource: ResourceRef) -> None:
        from awscleanup.config import PENDING_TAG_KEY, REASON_TAG_KEY

        ec2 = session.client("ec2", region_name=resource.region)
        ec2.delete_tags(
            Resources=[resource.resource_id],
            Tags=[{"Key": PENDING_TAG_KEY}, {"Key": REASON_TAG_KEY}],
        )

    def delete(self, session: boto3.Session, resource: ResourceRef) -> None:
        ec2 = session.client("ec2", region_name=resource.region)
        ec2.delete_snapshot(SnapshotId=resource.resource_id)


base.register(EbsSnapshotScanner())
