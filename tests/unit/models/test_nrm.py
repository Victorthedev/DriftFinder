import pytest

from driftfinder.models.enums import IaCTool
from driftfinder.models.nrm import (
    NRM_METADATA_FIELDS,
    NRMVPC,
    NRMCloudTrail,
    NRMEBSVolume,
    NRMIAMPolicy,
    NRMKMSKey,
    NRMRDSInstance,
    NRMS3Bucket,
    NRMSecurityGroup,
)


class TestNRMBase:
    def test_account_id_defaults_to_empty_string(self):
        bucket = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
        )
        assert bucket.account_id == ""

    def test_frozen_raises_on_mutation(self):
        bucket = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
        )
        with pytest.raises((TypeError, AttributeError)):
            bucket.resource_id = "changed"  # type: ignore[misc]

    def test_hashable(self):
        bucket = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=True,
        )
        s = {bucket}
        assert len(s) == 1


class TestNRMSecurityGroup:
    def test_ingress_rules_as_tuple(self):
        sg = NRMSecurityGroup(
            resource_id="sg-1",
            resource_name="sg-1",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            ingress_rules=((22, 22, "tcp"),),
        )
        assert isinstance(sg.ingress_rules, tuple)

    def test_hashable_with_rules(self):
        sg = NRMSecurityGroup(
            resource_id="sg-1",
            resource_name="sg-1",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            ingress_rules=((22, 22, "tcp"),),
            egress_rules=(),
        )
        assert hash(sg) is not None


class TestNRMMetadataFields:
    def test_metadata_fields_set(self):
        assert "resource_id" in NRM_METADATA_FIELDS
        assert "account_id" in NRM_METADATA_FIELDS
        assert "region" in NRM_METADATA_FIELDS
        assert "iac_tool" in NRM_METADATA_FIELDS

    def test_security_fields_not_in_metadata(self):
        assert "server_side_encryption_enabled" not in NRM_METADATA_FIELDS
        assert "unrestricted_ssh_ingress" not in NRM_METADATA_FIELDS


class TestNRMDefaultsAreNone:
    def test_all_security_fields_default_to_none(self):
        bucket = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
        )
        assert bucket.server_side_encryption_enabled is None
        assert bucket.public_access_block_enabled is None
        assert bucket.versioning_enabled is None
        assert bucket.access_logging_enabled is None

    def test_all_resource_types_construct(self):
        base = {
            "resource_id": "x",
            "resource_name": "x",
            "iac_tool": IaCTool.TERRAFORM,
            "region": "eu-west-2",
        }
        resources = [
            NRMS3Bucket(**base),
            NRMSecurityGroup(**base),
            NRMIAMPolicy(**base),
            NRMRDSInstance(**base),
            NRMEBSVolume(**base),
            NRMCloudTrail(**base),
            NRMVPC(**base),
            NRMKMSKey(**base),
        ]
        assert len(resources) == 8
