"""Scanner: idle load balancers (ALB/NLB via ELBv2, plus classic ELB) with
zero registered targets/instances.

A load balancer with nothing behind it is forwarding traffic to nowhere —
it's either a leftover from a decommissioned service or a broken deploy
either way, worth surfacing. We flag on zero *registered* targets (not just
zero *healthy* ones) to stay conservative: a target group with registered-
but-unhealthy targets might be a real, if broken, service, not clutter.
"""

from __future__ import annotations

import boto3

from awscleanup.config import Settings
from awscleanup.models import Finding, ResourceRef
from awscleanup.scanners import base
from awscleanup.scanners.tags import is_protected, resource_name, tags_to_dict

# Rough on-demand $/month, us-east-1, base hourly charge only (excludes LCU/
# data-processing charges, which are zero for an idle LB anyway).
_ESTIMATED_MONTHLY_COST_USD = {
    "application": 16.20,
    "network": 16.20,
    "gateway": 16.20,
    "classic": 18.00,
}


def _v2_registered_target_count(elbv2, lb_arn: str) -> int:
    try:
        target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)["TargetGroups"]
    except elbv2.exceptions.TargetGroupNotFoundException:
        return 0
    total = 0
    for tg in target_groups:
        health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
        total += len(health["TargetHealthDescriptions"])
    return total


class LoadBalancerScanner:
    resource_type = "load_balancer"

    def detect(self, session: boto3.Session, region: str, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_v2(session, region, settings))
        findings.extend(self._detect_classic(session, region, settings))
        return findings

    def _detect_v2(self, session, region, settings) -> list[Finding]:
        elbv2 = session.client("elbv2", region_name=region)
        findings = []
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                lb_arn = lb["LoadBalancerArn"]
                tags = tags_to_dict(
                    elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]["Tags"]
                )
                if is_protected(tags, settings):
                    continue
                if _v2_registered_target_count(elbv2, lb_arn) > 0:
                    continue

                lb_type = lb.get("Type", "application")
                resource = ResourceRef(
                    resource_type=self.resource_type,
                    resource_id=lb_arn,
                    region=region,
                    name=resource_name(tags) or lb.get("LoadBalancerName"),
                )
                findings.append(
                    Finding(
                        resource=resource,
                        reason="idle",
                        evidence=(
                            f"{lb_type} load balancer '{lb.get('LoadBalancerName')}' has zero "
                            f"registered targets across all its target groups"
                        ),
                        estimated_monthly_cost_usd=_ESTIMATED_MONTHLY_COST_USD.get(lb_type, 16.20),
                        extra={"lb_kind": "v2", "lb_type": lb_type},
                    )
                )
        return findings

    def _detect_classic(self, session, region, settings) -> list[Finding]:
        elb = session.client("elb", region_name=region)
        findings = []
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancerDescriptions"]:
                name = lb["LoadBalancerName"]
                if lb.get("Instances"):
                    continue

                tags = tags_to_dict(
                    elb.describe_tags(LoadBalancerNames=[name])["TagDescriptions"][0]["Tags"]
                )
                if is_protected(tags, settings):
                    continue

                resource = ResourceRef(
                    resource_type=self.resource_type,
                    resource_id=name,
                    region=region,
                    name=resource_name(tags) or name,
                )
                findings.append(
                    Finding(
                        resource=resource,
                        reason="idle",
                        evidence=f"classic load balancer '{name}' has zero registered instances",
                        estimated_monthly_cost_usd=_ESTIMATED_MONTHLY_COST_USD["classic"],
                        extra={"lb_kind": "classic", "lb_type": "classic"},
                    )
                )
        return findings

    def is_still_unused(
        self, session: boto3.Session, resource: ResourceRef
    ) -> tuple[bool, str]:
        if resource.resource_id.startswith("arn:"):
            elbv2 = session.client("elbv2", region_name=resource.region)
            try:
                elbv2.describe_load_balancers(LoadBalancerArns=[resource.resource_id])
            except elbv2.exceptions.LoadBalancerNotFoundException:
                return False, "load balancer no longer exists"
            count = _v2_registered_target_count(elbv2, resource.resource_id)
            if count > 0:
                return False, f"load balancer now has {count} registered target(s)"
            return True, "still zero registered targets"

        elb = session.client("elb", region_name=resource.region)
        try:
            resp = elb.describe_load_balancers(LoadBalancerNames=[resource.resource_id])
        except elb.exceptions.AccessPointNotFoundException:
            return False, "load balancer no longer exists"
        instances = resp["LoadBalancerDescriptions"][0].get("Instances", [])
        if instances:
            return False, f"load balancer now has {len(instances)} registered instance(s)"
        return True, "still zero registered instances"

    def tag_pending_deletion(
        self, session: boto3.Session, resource: ResourceRef, tags: dict[str, str]
    ) -> None:
        tag_spec = [{"Key": k, "Value": v} for k, v in tags.items()]
        if resource.resource_id.startswith("arn:"):
            elbv2 = session.client("elbv2", region_name=resource.region)
            elbv2.add_tags(ResourceArns=[resource.resource_id], Tags=tag_spec)
        else:
            elb = session.client("elb", region_name=resource.region)
            elb.add_tags(LoadBalancerNames=[resource.resource_id], Tags=tag_spec)

    def untag_pending_deletion(self, session: boto3.Session, resource: ResourceRef) -> None:
        from awscleanup.config import PENDING_TAG_KEY, REASON_TAG_KEY

        keys = [PENDING_TAG_KEY, REASON_TAG_KEY]
        if resource.resource_id.startswith("arn:"):
            elbv2 = session.client("elbv2", region_name=resource.region)
            elbv2.remove_tags(ResourceArns=[resource.resource_id], TagKeys=keys)
        else:
            elb = session.client("elb", region_name=resource.region)
            elb.remove_tags(
                LoadBalancerNames=[resource.resource_id], Tags=[{"Key": k} for k in keys]
            )

    def delete(self, session: boto3.Session, resource: ResourceRef) -> None:
        if resource.resource_id.startswith("arn:"):
            elbv2 = session.client("elbv2", region_name=resource.region)
            elbv2.delete_load_balancer(LoadBalancerArn=resource.resource_id)
        else:
            elb = session.client("elb", region_name=resource.region)
            elb.delete_load_balancer(LoadBalancerName=resource.resource_id)


base.register(LoadBalancerScanner())
