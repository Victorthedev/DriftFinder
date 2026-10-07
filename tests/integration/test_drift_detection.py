"""
Integration tests: full scan pipeline using moto-patched AWS.
No live AWS credentials required.
"""

import json

import boto3
from moto import mock_aws

from driftfinder.core.config import DriftFinderConfig
from driftfinder.core.engine import DriftFinderEngine
from driftfinder.models.enums import IaCTool


@mock_aws
def test_detects_encryption_drift_end_to_end(tmp_path):
    """Terraform state declares encryption; moto bucket has none. Engine finds drift."""
    session = boto3.Session(region_name="eu-west-1")
    s3 = session.client("s3")
    s3.create_bucket(
        Bucket="driftfinder-test",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )
    # Deliberately no encryption configured

    tfstate = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "test",
                "instances": [
                    {
                        "attributes": {
                            "id": "driftfinder-test",
                            "bucket": "driftfinder-test",
                            "region": "eu-west-1",
                        }
                    }
                ],
            },
            {
                "mode": "managed",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "name": "test",
                "instances": [
                    {
                        "attributes": {
                            "bucket": "driftfinder-test",
                            "rule": [
                                {
                                    "apply_server_side_encryption_by_default": [
                                        {"sse_algorithm": "AES256"}
                                    ]
                                }
                            ],
                        }
                    }
                ],
            },
        ],
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(tfstate))

    config = DriftFinderConfig(
        iac_tool=IaCTool.TERRAFORM,
        state_file=str(state_file),
        aws_region="eu-west-1",
    )
    engine = DriftFinderEngine(config)
    result = engine.scan()

    assert not result.compliant
    enc_findings = [
        f for f in result.findings if f.property_path == "server_side_encryption_enabled"
    ]
    assert len(enc_findings) == 1
    assert enc_findings[0].declared_value is True
    assert enc_findings[0].actual_value is False
    assert enc_findings[0].cis_controls == []


@mock_aws
def test_no_drift_when_state_matches(tmp_path):
    """When declared and actual state match, scan returns compliant."""
    session = boto3.Session(region_name="eu-west-1")
    s3 = session.client("s3")
    s3.create_bucket(
        Bucket="compliant-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )
    s3.put_bucket_versioning(
        Bucket="compliant-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    tfstate = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "compliant",
                "instances": [
                    {
                        "attributes": {
                            "id": "compliant-bucket",
                            "bucket": "compliant-bucket",
                            "region": "eu-west-1",
                        }
                    }
                ],
            },
            {
                "mode": "managed",
                "type": "aws_s3_bucket_versioning",
                "name": "compliant",
                "instances": [
                    {
                        "attributes": {
                            "bucket": "compliant-bucket",
                            "versioning_configuration": [
                                {"status": "Enabled", "mfa_delete": "Disabled"}
                            ],
                        }
                    }
                ],
            },
        ],
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(tfstate))

    config = DriftFinderConfig(
        iac_tool=IaCTool.TERRAFORM,
        state_file=str(state_file),
        aws_region="eu-west-1",
    )
    result = DriftFinderEngine(config).scan()
    versioning_findings = [f for f in result.findings if f.property_path == "versioning_enabled"]
    assert len(versioning_findings) == 0


@mock_aws
def test_deleted_resource_produces_critical_finding(tmp_path):
    """Resource in state file that does not exist in AWS produces DELETED finding."""
    # No bucket created in moto — simulates a deleted resource

    tfstate = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "gone",
                "instances": [
                    {
                        "attributes": {
                            "id": "deleted-bucket",
                            "bucket": "deleted-bucket",
                            "region": "eu-west-1",
                        }
                    }
                ],
            },
        ],
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(tfstate))

    config = DriftFinderConfig(
        iac_tool=IaCTool.TERRAFORM,
        state_file=str(state_file),
        aws_region="eu-west-1",
    )
    result = DriftFinderEngine(config).scan()

    assert not result.compliant
    deleted = [f for f in result.findings if f.property_path == "*"]
    assert len(deleted) == 1
    assert deleted[0].drift_type.value == "DELETED"
