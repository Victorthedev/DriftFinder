import boto3
import pytest
from moto import mock_aws

from driftfinder.models.enums import EncryptionAlgorithm, IaCTool
from driftfinder.models.nrm import NRMS3Bucket
from driftfinder.runtime.aws.s3 import S3Querier
from driftfinder.runtime.base import ResourceNotFoundError


def _declared(bucket_name: str, **kwargs) -> NRMS3Bucket:
    return NRMS3Bucket(
        resource_id=bucket_name,
        resource_name=bucket_name,
        iac_tool=IaCTool.TERRAFORM,
        region="eu-west-1",
        **kwargs,
    )


def _make_bucket(s3_client, name: str) -> None:
    s3_client.create_bucket(
        Bucket=name,
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )


@mock_aws
def test_detects_missing_encryption():
    session = boto3.Session(region_name="eu-west-1")
    _make_bucket(session.client("s3"), "test-bucket")

    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    result = querier.query(_declared("test-bucket"))
    assert result.server_side_encryption_enabled is False


@mock_aws
def test_detects_encryption_present():
    session = boto3.Session(region_name="eu-west-1")
    s3 = session.client("s3")
    _make_bucket(s3, "enc-bucket")
    s3.put_bucket_encryption(
        Bucket="enc-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    result = querier.query(_declared("enc-bucket"))
    assert result.server_side_encryption_enabled is True
    assert result.encryption_algorithm == EncryptionAlgorithm.AES256


@mock_aws
def test_public_access_block_all_enabled():
    session = boto3.Session(region_name="eu-west-1")
    s3 = session.client("s3")
    _make_bucket(s3, "pab-bucket")
    s3.put_public_access_block(
        Bucket="pab-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    result = querier.query(_declared("pab-bucket"))
    assert result.public_access_block_enabled is True
    assert result.block_public_acls is True


@mock_aws
def test_public_access_block_absent_returns_false():
    session = boto3.Session(region_name="eu-west-1")
    _make_bucket(session.client("s3"), "plain-bucket")
    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    result = querier.query(_declared("plain-bucket"))
    assert result.block_public_acls is False
    assert result.public_access_block_enabled is False


@mock_aws
def test_raises_resource_not_found_for_missing_bucket():
    session = boto3.Session(region_name="eu-west-1")
    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    with pytest.raises(ResourceNotFoundError):
        querier.query(_declared("does-not-exist"))


@mock_aws
def test_versioning_enabled():
    session = boto3.Session(region_name="eu-west-1")
    s3 = session.client("s3")
    _make_bucket(s3, "ver-bucket")
    s3.put_bucket_versioning(
        Bucket="ver-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    querier = S3Querier(session=session, region="eu-west-1", account_id="123456789012")
    result = querier.query(_declared("ver-bucket"))
    assert result.versioning_enabled is True
