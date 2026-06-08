import pytest

from driftfinder.mappers.cis_mapper import CISMapper
from driftfinder.mappers.cis_mappings import CIS_MAPPINGS
from driftfinder.models.enums import Severity


class TestCISMapper:
    def setup_method(self):
        self.mapper = CISMapper()

    def test_returns_control_for_known_field(self):
        ctrl = self.mapper.get_control("NRMS3Bucket", "server_side_encryption_enabled")
        assert ctrl is not None
        assert ctrl.control_id == "2.1.1"
        assert ctrl.severity == Severity.HIGH

    def test_returns_none_for_unknown_field(self):
        assert self.mapper.get_control("NRMS3Bucket", "nonexistent_field") is None

    def test_returns_none_for_unknown_resource_type(self):
        assert self.mapper.get_control("NRMUnknown", "server_side_encryption_enabled") is None

    @pytest.mark.parametrize(
        "resource_type,field,expected_id,expected_severity",
        [
            ("NRMS3Bucket", "public_access_block_enabled", "2.1.4", Severity.CRITICAL),
            ("NRMS3Bucket", "ssl_requests_only", "2.1.1", Severity.HIGH),
            ("NRMSecurityGroup", "unrestricted_ssh_ingress", "5.2", Severity.CRITICAL),
            ("NRMSecurityGroup", "unrestricted_rdp_ingress", "5.3", Severity.CRITICAL),
            ("NRMIAMPolicy", "has_wildcard_action", "1.16", Severity.CRITICAL),
            ("NRMRDSInstance", "storage_encrypted", "2.3.1", Severity.CRITICAL),
            ("NRMRDSInstance", "publicly_accessible", "2.3.2", Severity.HIGH),
            ("NRMEBSVolume", "encrypted", "2.2.1", Severity.CRITICAL),
            ("NRMCloudTrail", "multi_region_enabled", "3.1", Severity.HIGH),
            ("NRMCloudTrail", "is_logging", "3.1", Severity.CRITICAL),
            ("NRMVPC", "flow_logs_enabled", "5.1", Severity.HIGH),
            ("NRMVPC", "default_sg_has_no_rules", "5.5", Severity.CRITICAL),
            ("NRMKMSKey", "key_rotation_enabled", "3.7", Severity.HIGH),
            ("NRMKMSKey", "key_enabled", "3.7", Severity.CRITICAL),
        ],
    )
    def test_all_critical_controls_present(
        self, resource_type, field, expected_id, expected_severity
    ):
        ctrl = self.mapper.get_control(resource_type, field)
        assert ctrl is not None, f"Missing control for {resource_type}.{field}"
        assert ctrl.control_id == expected_id
        assert ctrl.severity == expected_severity

    def test_all_controls_for_type_s3(self):
        controls = self.mapper.all_controls_for_type("NRMS3Bucket")
        assert "server_side_encryption_enabled" in controls
        assert "public_access_block_enabled" in controls
        assert len(controls) == 11

    def test_total_mapping_count(self):
        assert len(CIS_MAPPINGS) == 31
