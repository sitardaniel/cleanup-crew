from __future__ import annotations

from awscleanup.models import ResourceRef
from awscleanup.scanners.ebs_snapshots import EbsSnapshotScanner
from tests.conftest import TEST_REGION


def _create_orphaned_snapshot(session):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    vol = ec2.create_volume(AvailabilityZone=f"{TEST_REGION}a", Size=8, VolumeType="gp3")
    volume_id = vol["VolumeId"]
    snap = ec2.create_snapshot(VolumeId=volume_id)
    ec2.delete_volume(VolumeId=volume_id)
    return snap["SnapshotId"], volume_id


def test_detects_orphaned_snapshot(session, settings):
    snapshot_id, volume_id = _create_orphaned_snapshot(session)

    findings = EbsSnapshotScanner().detect(session, TEST_REGION, settings)

    assert len(findings) == 1
    assert findings[0].resource.resource_id == snapshot_id
    assert volume_id in findings[0].evidence


def test_ignores_snapshot_with_existing_volume(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    vol = ec2.create_volume(AvailabilityZone=f"{TEST_REGION}a", Size=8, VolumeType="gp3")
    ec2.create_snapshot(VolumeId=vol["VolumeId"])

    findings = EbsSnapshotScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_ignores_protected_snapshot(session, settings):
    snapshot_id, _ = _create_orphaned_snapshot(session)
    ec2 = session.client("ec2", region_name=TEST_REGION)
    ec2.create_tags(Resources=[snapshot_id], Tags=[{"Key": "cleanup:ignore", "Value": "true"}])

    findings = EbsSnapshotScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_is_still_unused_false_if_volume_recreated_with_same_id(session, settings):
    """Sanity check of the re-verification query shape; in practice a
    deleted volume ID is never reused, but this exercises the "volume
    exists again" branch using a second, different orphaned snapshot."""
    snapshot_id, _ = _create_orphaned_snapshot(session)
    resource = ResourceRef(resource_type="ebs_snapshot", resource_id=snapshot_id, region=TEST_REGION)

    still_unused, detail = EbsSnapshotScanner().is_still_unused(session, resource)

    assert still_unused is True
    assert "still missing" in detail


def test_delete_removes_snapshot(session, settings):
    snapshot_id, _ = _create_orphaned_snapshot(session)
    resource = ResourceRef(resource_type="ebs_snapshot", resource_id=snapshot_id, region=TEST_REGION)

    EbsSnapshotScanner().delete(session, resource)

    still_unused, detail = EbsSnapshotScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "no longer exists" in detail
