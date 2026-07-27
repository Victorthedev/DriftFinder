from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from driftfinder.models.enums import DriftType, IaCTool, Severity
from driftfinder.models.findings import DriftFinding, ScanResult
from driftfinder.models.nrm import NRMS3Bucket


@pytest.fixture
def sample_drift_finding():
    return DriftFinding(
        resource_type="NRMS3Bucket",
        resource_id="test-bucket",
        resource_name="test-bucket",
        iac_tool="terraform",
        property_path="server_side_encryption_enabled",
        declared_value=True,
        actual_value=False,
        drift_type=DriftType.MODIFIED,
        severity=Severity.HIGH,
        cis_controls=["2.1.1"],
        cis_description="Ensure all S3 buckets employ encryption-at-rest",
        detected_at=datetime.now(tz=UTC),
    )


@pytest.fixture
def sample_scan_result(sample_drift_finding):
    return ScanResult(
        findings=[sample_drift_finding],
        scan_timestamp=datetime.now(tz=UTC),
        iac_tool="terraform",
        state_source="terraform.tfstate",
        resources_scanned=3,
        resources_with_drift=1,
        compliant=False,
        scan_duration_seconds=0.5,
    )


@pytest.fixture
def declared_s3_encrypted():
    return NRMS3Bucket(
        resource_id="my-bucket",
        resource_name="my-bucket",
        iac_tool=IaCTool.TERRAFORM,
        region="eu-west-1",
        server_side_encryption_enabled=True,
        public_access_block_enabled=True,
        versioning_enabled=True,
    )


@pytest.fixture
def moto_s3_bucket():
    """Yields a bucket name after creating it in moto-patched S3."""
    with mock_aws():
        session = boto3.Session(region_name="eu-west-1")
        s3 = session.client("s3")
        s3.create_bucket(
            Bucket="moto-test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
        )
        yield "moto-test-bucket", session
