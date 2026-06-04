from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, computed_field

from driftfinder.models.enums import DriftType, Severity


class DriftFinding(BaseModel):
    """
    A single detected drift instance.
    Formal tuple: f = (s, p, D(s)[p], A(s)[p], τ, σ, C)
    """

    model_config = ConfigDict(frozen=True)

    resource_type: str            # s  — NRM class name e.g. "NRMS3Bucket"
    resource_id: str              # s  — AWS resource identifier
    resource_name: str            # s  — human-readable name
    iac_tool: str                 # terraform | cloudformation | pulumi
    property_path: str            # p  — NRM property name
    declared_value: Any           # D(s)[p] — value in IaC state
    actual_value: Any             # A(s)[p] — value observed in AWS
    drift_type: DriftType         # τ  — MODIFIED | DELETED | UNMANAGED
    severity: Severity            # σ  — CRITICAL | HIGH | MEDIUM | LOW
    cis_controls: list[str]       # C  — CIS control IDs e.g. ["2.1.1"]
    cis_description: Optional[str] = None
    detected_at: Optional[datetime] = None


class ScanResult(BaseModel):
    """Complete result of one drift detection scan."""

    model_config = ConfigDict(frozen=True)

    findings: list[DriftFinding]
    scan_timestamp: datetime
    iac_tool: str
    state_source: str
    resources_scanned: int
    resources_with_drift: int
    compliant: bool
    scan_duration_seconds: float

    @computed_field  # type: ignore[misc]
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @computed_field  # type: ignore[misc]
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @computed_field  # type: ignore[misc]
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @computed_field  # type: ignore[misc]
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
