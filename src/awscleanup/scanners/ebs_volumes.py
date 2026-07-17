"""Scanner: unattached EBS volumes.

An EBS volume in `available` state (as opposed to `in-use`) is not attached
to any instance and is billed purely for storage with zero utility — one of
the safest, highest-confidence "unused" signals in AWS.
"""

from __future__ import annotations

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef, utcnow
from awscleanup.scanners import base
from awscleanup.scanners.tags import (
    dict_to_tag_spec,
    is_protected,
    resource_name,
    tags_to_dict,
)

# Rough on-demand $/GB-month, us-east-1 pricing as of 2026 — used only to
# give a ballpark estimate in reports, not billed precisely per region.
_PRICE_PER_GB_MONTH = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "sc1": 0.015,
    "st1": 0.045,
    "standard": 0.05,
}


class EbsVolumeScanner:
    resource_type = "ebs_volume"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page["Volumes"]:
                tags = tags_to_dict(vol.get("Tags"))
                if is_protected(tags, settings):
                    continue

                resource = ResourceRef(
                    resource_type=self.resource_type,
                    resource_id=vol["VolumeId"],
                    region=region,
                    name=resource_name(tags),
                )
                age_days = (utcnow() - vol["CreateTime"]).days
                size_gb = vol["Size"]
                vol_type = vol.get("VolumeType", "gp2")
                price_per_gb = _PRICE_PER_GB_MONTH.get(vol_type, 0.10)

                findings.append(
                    Finding(
                        resource=resource,
                        reason="unattached",
                        evidence=(
                            f"{size_gb}GiB {vol_type} volume, unattached, "
                            f"created {age_days}d ago"
                        ),
                        estimated_monthly_cost_usd=round(size_gb * price_per_gb, 2),
                        extra={"size_gb": size_gb, "volume_type": vol_type},
                    )
                )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        ec2 = session.client("ec2", region_name=resource.region)
        try:
            resp = ec2.describe_volumes(VolumeIds=[resource.resource_id])
        except ec2.exceptions.ClientError as e:
            if "InvalidVolume.NotFound" in str(e):
                return False, "volume no longer exists"
            raise
        volumes = resp["Volumes"]
        if not volumes:
            return False, "volume no longer exists"
        state = volumes[0]["State"]
        if state != "available":
            return False, f"volume state is now '{state}' (attached since tagging)"
        return True, "still unattached"

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
        ec2.delete_volume(VolumeId=resource.resource_id)


base.register(EbsVolumeScanner())
