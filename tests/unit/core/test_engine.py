from driftfinder.core.engine import DriftFinderEngine
from driftfinder.mappers.cis_mapper import CISMapper
from driftfinder.models.enums import DriftType, IaCTool, Severity
from driftfinder.models.nrm import NRMS3Bucket


def _engine() -> DriftFinderEngine:
    """Construct an engine without a real config or AWS session."""
    eng = DriftFinderEngine.__new__(DriftFinderEngine)
    eng.cis_mapper = CISMapper()
    return eng


class TestDetectDrift:
    def test_detects_encryption_drift(self):
        declared = NRMS3Bucket(
            resource_id="my-bucket",
            resource_name="my-bucket",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=True,
        )
        actual = declared.__class__(
            resource_id="my-bucket",
            resource_name="my-bucket",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=False,
        )
        findings = _engine()._detect_drift(declared, actual)
        assert len(findings) == 1
        f = findings[0]
        assert f.property_path == "server_side_encryption_enabled"
        assert f.declared_value is True
        assert f.actual_value is False
        assert f.drift_type == DriftType.MODIFIED
        assert "2.1.1" in f.cis_controls
        assert f.severity == Severity.HIGH

    def test_no_findings_when_state_matches(self):
        resource = NRMS3Bucket(
            resource_id="my-bucket",
            resource_name="my-bucket",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=True,
            public_access_block_enabled=True,
        )
        findings = _engine()._detect_drift(resource, resource)
        assert findings == []

    def test_none_declared_skipped(self):
        declared = NRMS3Bucket(
            resource_id="my-bucket",
            resource_name="my-bucket",
            iac_tool=IaCTool.CLOUDFORMATION,
            region="eu-west-2",
            server_side_encryption_enabled=None,
        )
        actual = NRMS3Bucket(
            resource_id="my-bucket",
            resource_name="my-bucket",
            iac_tool=IaCTool.CLOUDFORMATION,
            region="eu-west-2",
            server_side_encryption_enabled=False,
        )
        findings = _engine()._detect_drift(declared, actual)
        assert not any(f.property_path == "server_side_encryption_enabled" for f in findings)

    def test_multiple_drifted_properties(self):
        declared = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=True,
            versioning_enabled=True,
            access_logging_enabled=True,
        )
        actual = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            server_side_encryption_enabled=False,
            versioning_enabled=False,
            access_logging_enabled=False,
        )
        findings = _engine()._detect_drift(declared, actual)
        paths = {f.property_path for f in findings}
        assert "server_side_encryption_enabled" in paths
        assert "versioning_enabled" in paths
        assert "access_logging_enabled" in paths

    def test_unmapped_field_gets_low_severity(self):
        declared = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            mfa_delete_enabled=True,
        )
        actual = NRMS3Bucket(
            resource_id="b",
            resource_name="b",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
            mfa_delete_enabled=False,
        )
        findings = _engine()._detect_drift(declared, actual)
        mfa_finding = next((f for f in findings if f.property_path == "mfa_delete_enabled"), None)
        assert mfa_finding is not None
        assert mfa_finding.cis_controls == ["2.1.2"]


class TestClassifyDriftType:
    def test_modified_when_both_non_none(self):
        assert DriftFinderEngine._classify_drift_type(True, False) == DriftType.MODIFIED

    def test_deleted_when_actual_is_none(self):
        assert DriftFinderEngine._classify_drift_type(True, None) == DriftType.DELETED


class TestDeletedResourceFinding:
    def test_produces_critical_star_finding(self):
        resource = NRMS3Bucket(
            resource_id="gone-bucket",
            resource_name="gone-bucket",
            iac_tool=IaCTool.TERRAFORM,
            region="eu-west-2",
        )
        finding = _engine()._deleted_resource_finding(resource)
        assert finding.property_path == "*"
        assert finding.drift_type == DriftType.DELETED
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "gone-bucket"
