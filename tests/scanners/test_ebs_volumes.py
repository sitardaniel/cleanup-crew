from __future__ import annotations

from awscleanup.config import PENDING_TAG_KEY, REASON_TAG_KEY
from awscleanup.models import ResourceRef
from awscleanup.scanners.ebs_volumes import EbsVolumeScanner
from tests.conftest import TEST_REGION


def _create_volume(session, *, attach=False, tags=None):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    az = f"{TEST_REGION}a"
    vol = ec2.create_volume(AvailabilityZone=az, Size=10, VolumeType="gp3")
    volume_id = vol["VolumeId"]

    if tags:
        ec2.create_tags(
            Resources=[volume_id],
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )

    if attach:
        # Reserve/create a minimal instance to attach to.
        reservation = ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro"
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")

    return volume_id


def test_detects_unattached_volume(session, settings):
    volume_id = _create_volume(session)

    findings = EbsVolumeScanner().detect(session, TEST_REGION, settings)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource.resource_id == volume_id
    assert finding.reason == "unattached"
    assert finding.estimated_monthly_cost_usd == 0.8  # 10 GiB * $0.08/GiB gp3


def test_ignores_attached_volume(session, settings):
    _create_volume(session, attach=True)

    findings = EbsVolumeScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_ignores_protected_volume(session, settings):
    _create_volume(session, tags={"cleanup:ignore": "true"})

    findings = EbsVolumeScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_tag_and_untag_pending_deletion(session, settings):
    volume_id = _create_volume(session)
    resource = ResourceRef(resource_type="ebs_volume", resource_id=volume_id, region=TEST_REGION)
    scanner = EbsVolumeScanner()

    scanner.tag_pending_deletion(
        session, resource, {PENDING_TAG_KEY: "2026-08-01", REASON_TAG_KEY: "unattached"}
    )

    ec2 = session.client("ec2", region_name=TEST_REGION)
    tags = {t["Key"]: t["Value"] for t in ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Tags"]}
    assert tags[PENDING_TAG_KEY] == "2026-08-01"
    assert tags[REASON_TAG_KEY] == "unattached"

    scanner.untag_pending_deletion(session, resource)

    tags_after = {
        t["Key"]: t["Value"]
        for t in ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0].get("Tags", [])
    }
    assert PENDING_TAG_KEY not in tags_after
    assert REASON_TAG_KEY not in tags_after


def test_is_still_unused_true_for_untouched_volume(session, settings):
    volume_id = _create_volume(session)
    resource = ResourceRef(resource_type="ebs_volume", resource_id=volume_id, region=TEST_REGION)

    still_unused, detail = EbsVolumeScanner().is_still_unused(session, resource)

    assert still_unused is True


def test_is_still_unused_false_once_attached(session, settings):
    """Simulates the race the plan calls out: a volume gets tagged for
    deletion, then someone attaches it before sweep runs — sweep must skip it."""
    volume_id = _create_volume(session)
    resource = ResourceRef(resource_type="ebs_volume", resource_id=volume_id, region=TEST_REGION)

    ec2 = session.client("ec2", region_name=TEST_REGION)
    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = reservation["Instances"][0]["InstanceId"]
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")

    still_unused, detail = EbsVolumeScanner().is_still_unused(session, resource)

    assert still_unused is False
    assert "attached" in detail.lower()


def test_delete_removes_volume(session, settings):
    volume_id = _create_volume(session)
    resource = ResourceRef(resource_type="ebs_volume", resource_id=volume_id, region=TEST_REGION)

    EbsVolumeScanner().delete(session, resource)

    still_unused, detail = EbsVolumeScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "no longer exists" in detail
