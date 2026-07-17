"""Shared pytest fixtures: moto-mocked AWS, a boto3 session pointed at the
mock, and disposable Settings/StateStore instances per test."""

from __future__ import annotations

import os
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from awscleanup.config import Settings

TEST_REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _aws_credentials():
    """Ensure boto3 never accidentally reaches real AWS during tests, and
    keep moto's fixture set minimal. MOTO_EC2_LOAD_DEFAULT_AMIS=false
    disables moto's ~1000-entry seeded public AMI/snapshot catalog, which
    otherwise drowns out the handful of resources each test creates and
    breaks any test that lists *all* snapshots/AMIs in a region."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = TEST_REGION
    os.environ["MOTO_EC2_LOAD_DEFAULT_AMIS"] = "false"


@pytest.fixture
def aws():
    with mock_aws():
        yield


@pytest.fixture
def session(aws) -> boto3.Session:
    return boto3.Session(region_name=TEST_REGION)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(state_dir=tmp_path / ".awscleanup", grace_period_days=7)
