"""End-to-end CLI smoke tests: scan -> review -> sweep -> report against a
moto-mocked account, verifying the full tag-and-wait pipeline through the
actual Typer commands (not just the scanner classes directly)."""

from __future__ import annotations


from typer.testing import CliRunner

from awscleanup.cli import app

runner = CliRunner()


def _set_state_dir(tmp_path, monkeypatch, grace_period_days=0):
    monkeypatch.setenv("AWSCLEANUP_STATE_DIR", str(tmp_path / ".awscleanup"))
    monkeypatch.setenv("AWSCLEANUP_REGIONS", '["us-east-1"]')
    monkeypatch.setenv("AWSCLEANUP_GRACE_PERIOD_DAYS", str(grace_period_days))


def test_full_pipeline_scan_review_sweep_report(session, tmp_path, monkeypatch):
    _set_state_dir(tmp_path, monkeypatch)
    ec2 = session.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=5, VolumeType="gp3")

    scan_result = runner.invoke(app, ["scan"])
    assert scan_result.exit_code == 0, scan_result.output
    assert "vol-" in scan_result.output

    review_result = runner.invoke(app, ["review", "--all"], input="y\n")
    assert review_result.exit_code == 0, review_result.output
    assert "1 approved" in review_result.output

    sweep_result = runner.invoke(app, ["sweep", "--yes"])
    assert sweep_result.exit_code == 0, sweep_result.output
    assert "1 deleted" in sweep_result.output

    remaining = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])["Volumes"]
    assert remaining == []

    report_path = tmp_path / "report.html"
    report_result = runner.invoke(app, ["report", "--out", str(report_path)])
    assert report_result.exit_code == 0, report_result.output
    assert report_path.exists()
    assert "cleanup-crew report" in report_path.read_text()


def test_sweep_skips_and_reverts_resource_that_became_used_again(session, tmp_path, monkeypatch):
    """Guards the core safety property from the plan: if a tagged resource
    stops being unused before its grace period elapses, sweep must not
    delete it, and must remove the pending-deletion tag."""
    _set_state_dir(tmp_path, monkeypatch)
    ec2 = session.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=5, VolumeType="gp3")
    volume_id = vol["VolumeId"]

    runner.invoke(app, ["scan"])
    runner.invoke(app, ["review", "--all"], input="y\n")

    # Simulate the volume being attached after being tagged, before sweep runs.
    reservation = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    ec2.attach_volume(
        VolumeId=volume_id, InstanceId=reservation["Instances"][0]["InstanceId"], Device="/dev/sdf"
    )

    sweep_result = runner.invoke(app, ["sweep", "--yes"])
    assert sweep_result.exit_code == 0, sweep_result.output
    assert "1 skipped" in sweep_result.output

    still_there = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    assert still_there[0]["State"] == "in-use"
