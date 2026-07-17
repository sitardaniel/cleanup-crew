"""Scanner: unassociated Elastic IPs.

AWS bills idle (unassociated) Elastic IPs by the hour. An EIP with no
AssociationId is doing nothing but costing money — high-confidence signal.
"""

from __future__ import annotations

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef
from awscleanup.scanners import base
from awscleanup.scanners.tags import dict_to_tag_spec, is_protected, resource_name, tags_to_dict

# AWS started charging for idle public IPv4 addresses in 2024; ~$0.005/hr.
_ESTIMATED_MONTHLY_COST_USD = round(0.005 * 24 * 30, 2)


class ElasticIpScanner:
    resource_type = "elastic_ip"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        findings: list[Finding] = []

        for addr in ec2.describe_addresses()["Addresses"]:
            if addr.get("AssociationId") or addr.get("InstanceId"):
                continue  # associated

            tags = tags_to_dict(addr.get("Tags"))
            if is_protected(tags, settings):
                continue

            resource_id = addr.get("AllocationId") or addr["PublicIp"]
            resource = ResourceRef(
                resource_type=self.resource_type,
                resource_id=resource_id,
                region=region,
                name=resource_name(tags),
            )
            findings.append(
                Finding(
                    resource=resource,
                    reason="unassociated",
                    evidence=f"Elastic IP {addr['PublicIp']} is not associated with any resource",
                    estimated_monthly_cost_usd=_ESTIMATED_MONTHLY_COST_USD,
                    extra={"public_ip": addr["PublicIp"]},
                )
            )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        ec2 = session.client("ec2", region_name=resource.region)
        try:
            resp = ec2.describe_addresses(AllocationIds=[resource.resource_id])
        except ec2.exceptions.ClientError as e:
            if "InvalidAllocationID.NotFound" in str(e) or "InvalidAddress.NotFound" in str(e):
                return False, "address no longer exists"
            raise
        addresses = resp["Addresses"]
        if not addresses:
            return False, "address no longer exists"
        addr = addresses[0]
        if addr.get("AssociationId") or addr.get("InstanceId"):
            return False, "address has since been associated"
        return True, "still unassociated"

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
        ec2.release_address(AllocationId=resource.resource_id)


base.register(ElasticIpScanner())
