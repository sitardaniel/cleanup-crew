"""boto3 session/client helpers, including multi-region discovery."""

from __future__ import annotations

import boto3

from awscleanup.config import Settings


def get_session(settings: Settings) -> boto3.Session:
    return boto3.Session(profile_name=settings.profile)


def get_account_id(session: boto3.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


def enabled_regions(session: boto3.Session, settings: Settings) -> list[str]:
    """Regions to scan: explicit config wins; otherwise discover every region
    enabled for this account via EC2's DescribeRegions."""
    if settings.regions:
        return list(settings.regions)

    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def client(session: boto3.Session, service: str, region: str):
    return session.client(service, region_name=region)
