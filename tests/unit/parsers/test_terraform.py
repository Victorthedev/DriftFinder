from pathlib import Path

import pytest

from driftfinder.models.enums import EncryptionAlgorithm
from driftfinder.models.nrm import NRMS3Bucket, NRMSecurityGroup
from driftfinder.parsers.terraform import TerraformParser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "tfstate"


def _s3(path: Path) -> list:
    parser = TerraformParser(region="eu-west-2")
    return [r for r in parser.parse(str(path)) if isinstance(r, NRMS3Bucket)]


def _sg(path: Path) -> list:
    parser = TerraformParser(region="eu-west-2")
    return [r for r in parser.parse(str(path)) if isinstance(r, NRMSecurityGroup)]


class TestTerraformS3Parser:
    def test_parses_encrypted_bucket(self):
        buckets = _s3(FIXTURES / "s3_encrypted.json")
        assert len(buckets) == 1
        assert buckets[0].server_side_encryption_enabled is True
        assert buckets[0].encryption_algorithm == EncryptionAlgorithm.AES256

    def test_parses_bucket_without_encryption(self):
        buckets = _s3(FIXTURES / "s3_no_encryption.json")
        assert len(buckets) == 1
        assert buckets[0].server_side_encryption_enabled is None

    def test_handles_modern_split_resource_format(self):
        buckets = _s3(FIXTURES / "s3_modern_split_format.json")
        assert len(buckets) == 1
        assert buckets[0].block_public_acls is True
        assert buckets[0].ignore_public_acls is True
        assert buckets[0].block_public_policy is True
        assert buckets[0].restrict_public_buckets is True
        assert buckets[0].public_access_block_enabled is True

    def test_bucket_id_matches_fixture(self):
        buckets = _s3(FIXTURES / "s3_encrypted.json")
        assert buckets[0].resource_id == "test-encrypted-bucket"

    def test_version_mismatch_raises(self, tmp_path):
        bad = tmp_path / "bad.tfstate"
        bad.write_text('{"version": 3, "resources": []}')
        with pytest.raises(ValueError, match="version"):
            list(TerraformParser().parse(str(bad)))

    def test_no_encryption_means_none_not_false(self):
        buckets = _s3(FIXTURES / "s3_no_encryption.json")
        assert buckets[0].server_side_encryption_enabled is None


class TestTerraformSecurityGroupParser:
    def test_parses_security_group(self):
        sgs = _sg(FIXTURES / "security_group.json")
        assert len(sgs) == 1

    def test_no_unrestricted_ssh(self):
        # Empty ingress list → None per the None-vs-False invariant (absent, not False)
        sgs = _sg(FIXTURES / "security_group.json")
        assert sgs[0].unrestricted_ssh_ingress is None

    def test_no_unrestricted_all_traffic(self):
        sgs = _sg(FIXTURES / "security_group.json")
        assert sgs[0].unrestricted_all_traffic_ingress is None

    def test_sg_id_matches_fixture(self):
        sgs = _sg(FIXTURES / "security_group.json")
        assert sgs[0].resource_id == "sg-test123"
