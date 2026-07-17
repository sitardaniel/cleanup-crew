from __future__ import annotations

from awscleanup.models import ResourceRef
from awscleanup.scanners.ec2_instances import Ec2InstanceScanner
from tests.conftest import TEST_REGION


def _create_stopped_instance(session):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = reservation["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])
    return instance_id


def test_detects_stopped_instance_past_threshold(session, settings):
    instance_id = _create_stopped_instance(session)
    # Instance just stopped (age ~0d); use a 0-day threshold so we can test
    # the flagging logic without manipulating time.
    zero_threshold = settings.model_copy(update={"stopped_instance_threshold_days": 0})

    findings = Ec2InstanceScanner().detect(session, TEST_REGION, zero_threshold)

    assert len(findings) == 1
    assert findings[0].resource.resource_id == instance_id
    assert findings[0].reason == "stopped"


def test_does_not_flag_recently_stopped_instance_under_default_threshold(session, settings):
    _create_stopped_instance(session)
    # Default threshold is 14 days; a just-stopped instance shouldn't be flagged.
    findings = Ec2InstanceScanner().detect(session, TEST_REGION, settings)

    assert findings == []


def test_ignores_running_instance(session, settings):
    ec2 = session.client("ec2", region_name=TEST_REGION)
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    zero_threshold = settings.model_copy(update={"stopped_instance_threshold_days": 0})

    findings = Ec2InstanceScanner().detect(session, TEST_REGION, zero_threshold)

    assert findings == []


def test_ignores_protected_stopped_instance(session, settings):
    instance_id = _create_stopped_instance(session)
    ec2 = session.client("ec2", region_name=TEST_REGION)
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "cleanup:ignore", "Value": "true"}])
    zero_threshold = settings.model_copy(update={"stopped_instance_threshold_days": 0})

    findings = Ec2InstanceScanner().detect(session, TEST_REGION, zero_threshold)

    assert findings == []


def test_is_still_unused_false_once_restarted(session, settings):
    instance_id = _create_stopped_instance(session)
    resource = ResourceRef(resource_type="ec2_instance", resource_id=instance_id, region=TEST_REGION)

    ec2 = session.client("ec2", region_name=TEST_REGION)
    ec2.start_instances(InstanceIds=[instance_id])

    still_unused, detail = Ec2InstanceScanner().is_still_unused(session, resource)
    assert still_unused is False


def test_delete_terminates_instance(session, settings):
    instance_id = _create_stopped_instance(session)
    resource = ResourceRef(resource_type="ec2_instance", resource_id=instance_id, region=TEST_REGION)

    Ec2InstanceScanner().delete(session, resource)

    still_unused, detail = Ec2InstanceScanner().is_still_unused(session, resource)
    assert still_unused is False
    assert "terminated" in detail.lower() or "state is now" in detail.lower()
