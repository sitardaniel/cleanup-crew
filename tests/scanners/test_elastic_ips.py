from __future__ import annotations

from awscleanup.models import ResourceRef
from awscleanup.scanners.elastic_ips import ElasticIpScanner
from tests.conftest import TEST_REGION


def test_detects_unassociated_eip(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    addr = ec2.allocate_address(Domain="vpc")

    findings = ElasticIpScanner().detect(session, TEST_REGION, settings)

    assert len(findings) == 1
    assert findings[0].resource.resource_id == addr["AllocationId"]
    assert findings[0].reason == "unassociated"


def test_ignores_associated_eip(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    addr = ec2.allocate_address(Domain="vpc")
    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = reservation["Instances"][0]["InstanceId"]
    ec2.associate_address(AllocationId=addr["AllocationId"], InstanceId=instance_id)

    findings = ElasticIpScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_ignores_protected_eip(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    addr = ec2.allocate_address(Domain="vpc")
    ec2.create_tags(
        Resources=[addr["AllocationId"]], Tags=[{"Key": "cleanup:ignore", "Value": "true"}]
    )

    findings = ElasticIpScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_is_still_unused_false_once_associated(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    addr = ec2.allocate_address(Domain="vpc")
    resource = ResourceRef(
        resource_type="elastic_ip", resource_id=addr["AllocationId"], region=TEST_REGION
    )

    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    ec2.associate_address(
        AllocationId=addr["AllocationId"], InstanceId=reservation["Instances"][0]["InstanceId"]
    )

    still_unused, detail = ElasticIpScanner().is_still_unused(session, resource)
    assert still_unused is False


def test_delete_releases_address(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    addr = ec2.allocate_address(Domain="vpc")
    resource = ResourceRef(
        resource_type="elastic_ip", resource_id=addr["AllocationId"], region=TEST_REGION
    )

    ElasticIpScanner().delete(session, resource)

    still_unused, detail = ElasticIpScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "no longer exists" in detail
