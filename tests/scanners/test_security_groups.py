from __future__ import annotations

from awscleanup.models import ResourceRef
from awscleanup.scanners.security_groups import SecurityGroupScanner
from tests.conftest import TEST_REGION


def test_detects_unused_security_group(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    sg = ec2.create_security_group(GroupName="unused-sg", Description="unused")

    findings = SecurityGroupScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert sg["GroupId"] in ids


def test_ignores_default_security_group(session, settings):
    findings = SecurityGroupScanner().detect(session, TEST_REGION, settings)

    names = [f.extra["group_name"] for f in findings]
    assert "default" not in names


def test_ignores_security_group_attached_to_eni(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    sg = ec2.create_security_group(GroupName="attached-sg", Description="attached")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.5.0/24", AvailabilityZone=f"{TEST_REGION}a")
    ec2.create_network_interface(SubnetId=subnet["Subnet"]["SubnetId"], Groups=[sg["GroupId"]])

    findings = SecurityGroupScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert sg["GroupId"] not in ids


def test_ignores_security_group_referenced_by_another_group(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    referenced_sg = ec2.create_security_group(GroupName="referenced-sg", Description="referenced")
    referencing_sg = ec2.create_security_group(GroupName="referencing-sg", Description="referencing")
    ec2.authorize_security_group_ingress(
        GroupId=referencing_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "UserIdGroupPairs": [{"GroupId": referenced_sg["GroupId"]}],
            }
        ],
    )

    findings = SecurityGroupScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert referenced_sg["GroupId"] not in ids
    # referencing_sg itself is still unattached/unreferenced, so it IS flagged
    assert referencing_sg["GroupId"] in ids


def test_ignores_protected_security_group(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    sg = ec2.create_security_group(GroupName="ignored-sg", Description="ignored")
    ec2.create_tags(Resources=[sg["GroupId"]], Tags=[{"Key": "cleanup:ignore", "Value": "true"}])

    findings = SecurityGroupScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert sg["GroupId"] not in ids


def test_delete_removes_security_group(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    sg = ec2.create_security_group(GroupName="to-delete-sg", Description="to delete")
    resource = ResourceRef(resource_type="security_group", resource_id=sg["GroupId"], region=TEST_REGION)

    SecurityGroupScanner().delete(session, resource)

    still_unused, detail = SecurityGroupScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "no longer exists" in detail
