"""Scanner: EC2 instances stopped longer than a configurable threshold.

A stopped instance still incurs EBS storage cost (and, for reserved/allocated
capacity, sometimes more) with zero compute value. We only flag instances
where the stop date can be confidently determined from
`StateTransitionReason` — if AWS doesn't tell us when it stopped, we don't
guess, to keep this scanner high-confidence.
"""

from __future__ import annotations

import re

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef, utcnow
from awscleanup.scanners import base
from awscleanup.scanners.tags import dict_to_tag_spec, is_protected, resource_name, tags_to_dict

# e.g. "User initiated (2026-07-17 02:52:45 UTC)"
_STOP_DATE_RE = re.compile(r"\(([\d-]+ [\d:]+)\s+(?:UTC|GMT)\)")


def _parse_stopped_since(state_transition_reason: str):
    match = _STOP_DATE_RE.search(state_transition_reason or "")
    if not match:
        return None
    from datetime import datetime, timezone

    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


class Ec2InstanceScanner:
    resource_type = "ec2_instance"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    stopped_since = _parse_stopped_since(instance.get("StateTransitionReason", ""))
                    if stopped_since is None:
                        continue  # can't confidently determine duration; skip

                    age_days = (utcnow() - stopped_since).days
                    if age_days < settings.stopped_instance_threshold_days:
                        continue

                    tags = tags_to_dict(instance.get("Tags"))
                    if is_protected(tags, settings):
                        continue

                    resource = ResourceRef(
                        resource_type=self.resource_type,
                        resource_id=instance["InstanceId"],
                        region=region,
                        name=resource_name(tags),
                    )
                    findings.append(
                        Finding(
                            resource=resource,
                            reason="stopped",
                            evidence=(
                                f"{instance.get('InstanceType', '?')} instance stopped "
                                f"{age_days}d ago (threshold: "
                                f"{settings.stopped_instance_threshold_days}d)"
                            ),
                            estimated_monthly_cost_usd=None,  # EBS-only cost; varies per volume
                            extra={"instance_type": instance.get("InstanceType")},
                        )
                    )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        ec2 = session.client("ec2", region_name=resource.region)
        try:
            resp = ec2.describe_instances(InstanceIds=[resource.resource_id])
        except ec2.exceptions.ClientError as e:
            if "InvalidInstanceID.NotFound" in str(e):
                return False, "instance no longer exists"
            raise
        instances = [i for r in resp["Reservations"] for i in r["Instances"]]
        if not instances:
            return False, "instance no longer exists"
        state = instances[0]["State"]["Name"]
        if state != "stopped":
            return False, f"instance state is now '{state}'"
        return True, "still stopped"

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
        """"Delete" for a stopped instance means terminate — there's no
        lesser-destructive action available once you've decided it's unused."""
        ec2 = session.client("ec2", region_name=resource.region)
        ec2.terminate_instances(InstanceIds=[resource.resource_id])


base.register(Ec2InstanceScanner())
