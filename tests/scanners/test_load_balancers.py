from __future__ import annotations

from awscleanup.models import ResourceRef
from awscleanup.scanners.load_balancers import LoadBalancerScanner
from tests.conftest import TEST_REGION


def _create_vpc_and_subnets(session):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sub1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{TEST_REGION}a")["Subnet"]["SubnetId"]
    sub2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone=f"{TEST_REGION}b")["Subnet"]["SubnetId"]
    return vpc_id, [sub1, sub2]


def test_detects_idle_alb_with_no_target_groups(session, settings):
    _, subnets = _create_vpc_and_subnets(session)
    elbv2 = session.client("elbv2", region_name=TEST_REGION)
    lb = elbv2.create_load_balancer(Name="idle-alb", Subnets=subnets, Type="application")
    lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]

    findings = LoadBalancerScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert lb_arn in ids


def test_detects_idle_classic_lb(session, settings):
    elb = session.client("elb", region_name=TEST_REGION)
    elb.create_load_balancer(
        LoadBalancerName="idle-clb",
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        AvailabilityZones=[f"{TEST_REGION}a"],
    )

    findings = LoadBalancerScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert "idle-clb" in ids


def test_ignores_classic_lb_with_registered_instance(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = reservation["Instances"][0]["InstanceId"]

    elb = session.client("elb", region_name=TEST_REGION)
    elb.create_load_balancer(
        LoadBalancerName="active-clb",
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        AvailabilityZones=[f"{TEST_REGION}a"],
    )
    elb.register_instances_with_load_balancer(
        LoadBalancerName="active-clb", Instances=[{"InstanceId": instance_id}]
    )

    findings = LoadBalancerScanner().detect(session, TEST_REGION, settings)

    ids = [f.resource.resource_id for f in findings]
    assert "active-clb" not in ids


def test_delete_removes_classic_lb(session, settings):
    elb = session.client("elb", region_name=TEST_REGION)
    elb.create_load_balancer(
        LoadBalancerName="to-delete-clb",
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        AvailabilityZones=[f"{TEST_REGION}a"],
    )
    resource = ResourceRef(resource_type="load_balancer", resource_id="to-delete-clb", region=TEST_REGION)

    LoadBalancerScanner().delete(session, resource)

    still_unused, detail = LoadBalancerScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "no longer exists" in detail
