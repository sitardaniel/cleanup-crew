"""Scanner: unused security groups.

A security group that isn't attached to any network interface and isn't
referenced by any other security group's rules is dead configuration —
safe to remove. The account's default security groups are always excluded:
AWS won't let you delete a VPC's default group anyway.
"""

from __future__ import annotations

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef
from awscleanup.scanners import base
from awscleanup.scanners.tags import dict_to_tag_spec, is_protected, resource_name, tags_to_dict


def _attached_group_ids(ec2) -> set[str]:
    ids: set[str] = set()
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        for eni in page["NetworkInterfaces"]:
            ids.update(g["GroupId"] for g in eni.get("Groups", []))
    return ids


def _referenced_group_ids(all_groups: list[dict]) -> set[str]:
    """Security group IDs referenced as a source/destination in any other
    group's ingress/egress rules (UserIdGroupPairs)."""
    ids: set[str] = set()
    for sg in all_groups:
        for rule in [*sg.get("IpPermissions", []), *sg.get("IpPermissionsEgress", [])]:
            for pair in rule.get("UserIdGroupPairs", []):
                if pair.get("GroupId"):
                    ids.add(pair["GroupId"])
    return ids


class SecurityGroupScanner:
    resource_type = "security_group"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        all_groups = ec2.describe_security_groups()["SecurityGroups"]

        attached = _attached_group_ids(ec2)
        referenced = _referenced_group_ids(all_groups)
        findings: list[Finding] = []

        for sg in all_groups:
            if sg["GroupName"] == "default":
                continue  # AWS won't let you delete the default group
            group_id = sg["GroupId"]
            if group_id in attached or group_id in referenced:
                continue

            tags = tags_to_dict(sg.get("Tags"))
            if is_protected(tags, settings):
                continue

            resource = ResourceRef(
                resource_type=self.resource_type,
                resource_id=group_id,
                region=region,
                name=resource_name(tags) or sg["GroupName"],
            )
            findings.append(
                Finding(
                    resource=resource,
                    reason="unused",
                    evidence=(
                        f"security group '{sg['GroupName']}' is not attached to any "
                        f"network interface and not referenced by other security groups"
                    ),
                    estimated_monthly_cost_usd=0.0,
                    extra={"group_name": sg["GroupName"]},
                )
            )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        ec2 = session.client("ec2", region_name=resource.region)
        try:
            resp = ec2.describe_security_groups(GroupIds=[resource.resource_id])
        except ec2.exceptions.ClientError as e:
            if "InvalidGroup.NotFound" in str(e):
                return False, "security group no longer exists"
            raise
        groups = resp["SecurityGroups"]
        if not groups:
            return False, "security group no longer exists"

        attached = _attached_group_ids(ec2)
        if resource.resource_id in attached:
            return False, "security group is now attached to a network interface"

        all_groups = ec2.describe_security_groups()["SecurityGroups"]
        if resource.resource_id in _referenced_group_ids(all_groups):
            return False, "security group is now referenced by another group's rules"

        return True, "still unused"

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
        ec2.delete_security_group(GroupId=resource.resource_id)


base.register(SecurityGroupScanner())
