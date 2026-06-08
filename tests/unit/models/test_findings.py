from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from driftfinder.models.enums import DriftType, Severity
from driftfinder.models.findings import DriftFinding, ScanResult


def _make_finding(severity: Severity) -> DriftFinding:
    return DriftFinding(
        resource_type="NRMS3Bucket",
        resource_id="b",
        resource_name="b",
        iac_tool="terraform",
        property_path="server_side_encryption_enabled",
        declared_value=True,
        actual_value=False,
        drift_type=DriftType.MODIFIED,
        severity=severity,
        cis_controls=["2.1.1"],
        detected_at=datetime.now(tz=UTC),
    )


def _make_result(findings: list) -> ScanResult:
    return ScanResult(
        findings=findings,
        scan_timestamp=datetime.now(tz=UTC),
        iac_tool="terraform",
        state_source="terraform.tfstate",
        resources_scanned=5,
        resources_with_drift=len(findings),
        compliant=len(findings) == 0,
        scan_duration_seconds=1.0,
    )


class TestScanResultCounts:
    def test_counts_by_severity(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
            _make_finding(Severity.LOW),
        ]
        result = _make_result(findings)
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1

    def test_zero_counts_when_no_findings(self):
        result = _make_result([])
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.compliant is True

    def test_compliant_false_when_findings_present(self):
        result = _make_result([_make_finding(Severity.LOW)])
        assert result.compliant is False


class TestDriftFinding:
    def test_frozen(self, sample_drift_finding):
        with pytest.raises((TypeError, AttributeError, ValidationError)):
            sample_drift_finding.severity = Severity.LOW  # type: ignore[misc]

    def test_cis_controls_list(self, sample_drift_finding):
        assert isinstance(sample_drift_finding.cis_controls, list)
        assert "2.1.1" in sample_drift_finding.cis_controls
