import logging
import time
from datetime import UTC, datetime

from driftfinder.core.config import DriftFinderConfig
from driftfinder.mappers.cis_mapper import CISMapper
from driftfinder.models.enums import DriftType, IaCTool, Severity
from driftfinder.models.findings import DriftFinding, ScanResult
from driftfinder.models.nrm import NRM_METADATA_FIELDS, NRMResource
from driftfinder.parsers.base import BaseParser
from driftfinder.parsers.cloudformation import CloudFormationParser
from driftfinder.parsers.pulumi import PulumiParser
from driftfinder.parsers.terraform import TerraformParser
from driftfinder.runtime.base import ResourceNotFoundError
from driftfinder.runtime.client import AWSRuntimeQuerier

logger = logging.getLogger(__name__)


class DriftFinderEngine:
    """
    Orchestrates the four-layer detection pipeline.

    Layer 1: IaC Parser     -> declared NRM objects
    Layer 2: NRM schema     -> normalised, tool-agnostic representation
    Layer 3: Runtime querier -> actual NRM objects from AWS
    Layer 4: Drift detection + CIS mapping -> DriftFindings
    """

    def __init__(self, config: DriftFinderConfig) -> None:
        self.config = config
        self.parser = self._build_parser(config)
        self.runtime = AWSRuntimeQuerier(
            region=config.aws_region,
            profile=config.aws_profile,
        )
        self.cis_mapper = CISMapper()

    # Public API

    def scan(self) -> ScanResult:
        start = time.monotonic()
        source = self._state_source()

        logger.info("Parsing declared state from %s (%s)", source, self.config.iac_tool.value)
        declared_resources = list(self.parser.parse(source))
        logger.info("Found %d declared resources", len(declared_resources))

        findings: list[DriftFinding] = []
        resources_with_drift: set[str] = set()

        for declared in declared_resources:
            try:
                actual = self.runtime.query(declared)
            except ResourceNotFoundError as exc:
                logger.warning(
                    "Resource not found in AWS: %s/%s", exc.resource_type, exc.resource_id
                )
                findings.append(self._deleted_resource_finding(declared))
                resources_with_drift.add(declared.resource_id)
                continue
            except Exception as exc:
                logger.error(
                    "Unexpected error querying %s %s: %s",
                    type(declared).__name__,
                    declared.resource_id,
                    exc,
                )
                continue

            resource_findings = self._detect_drift(declared, actual)
            findings.extend(resource_findings)
            if resource_findings:
                resources_with_drift.add(declared.resource_id)

        duration = time.monotonic() - start
        logger.info(
            "Scan complete: %d resources, %d findings, %.2fs",
            len(declared_resources),
            len(findings),
            duration,
        )

        return ScanResult(
            findings=findings,
            scan_timestamp=datetime.now(tz=UTC),
            iac_tool=self.config.iac_tool.value,
            state_source=source,
            resources_scanned=len(declared_resources),
            resources_with_drift=len(resources_with_drift),
            compliant=len(findings) == 0,
            scan_duration_seconds=round(duration, 3),
        )

    # Internal helpers

    def _detect_drift(self, declared: NRMResource, actual: NRMResource) -> list[DriftFinding]:
        """
        Property-by-property comparison implementing:
            Drift(s) = { p in P(s) | D(s)[p] != A(s)[p] }

        Skips any property where declared_value is None — that means the
        property was absent from the IaC source, not explicitly set to False.
        """
        findings: list[DriftFinding] = []
        resource_type = type(declared).__name__

        for field_name in declared.__dataclass_fields__:
            if field_name in NRM_METADATA_FIELDS:
                continue

            declared_value = getattr(declared, field_name)
            if declared_value is None:
                continue  # Not declared in IaC; skip to avoid false positives

            actual_value = getattr(actual, field_name)
            if declared_value == actual_value:
                continue

            cis = self.cis_mapper.get_control(resource_type, field_name)
            findings.append(
                DriftFinding(
                    resource_type=resource_type,
                    resource_id=declared.resource_id,
                    resource_name=declared.resource_name,
                    iac_tool=(
                        declared.iac_tool.value
                        if hasattr(declared.iac_tool, "value")
                        else str(declared.iac_tool)
                    ),
                    property_path=field_name,
                    declared_value=declared_value,
                    actual_value=actual_value,
                    drift_type=self._classify_drift_type(declared_value, actual_value),
                    severity=cis.severity if cis else Severity.LOW,
                    cis_controls=[cis.control_id] if cis and cis.control_id else [],
                    cis_description=cis.description if cis else None,
                    detected_at=datetime.now(tz=UTC),
                )
            )

        return findings

    def _deleted_resource_finding(self, declared: NRMResource) -> DriftFinding:
        """Produce a single DELETED finding for a resource that no longer exists in AWS."""
        resource_type = type(declared).__name__
        return DriftFinding(
            resource_type=resource_type,
            resource_id=declared.resource_id,
            resource_name=declared.resource_name,
            iac_tool=(
                declared.iac_tool.value
                if hasattr(declared.iac_tool, "value")
                else str(declared.iac_tool)
            ),
            property_path="*",
            declared_value="<exists>",
            actual_value=None,
            drift_type=DriftType.DELETED,
            severity=Severity.CRITICAL,
            cis_controls=[],
            cis_description="Resource declared in IaC no longer exists in AWS",
            detected_at=datetime.now(tz=UTC),
        )

    @staticmethod
    def _classify_drift_type(declared_value: object, actual_value: object) -> DriftType:
        if actual_value is None:
            return DriftType.DELETED
        return DriftType.MODIFIED

    def _state_source(self) -> str:
        if self.config.iac_tool == IaCTool.TERRAFORM:
            if not self.config.state_file:
                raise ValueError("state_file is required for Terraform scans")
            return self.config.state_file
        if self.config.iac_tool == IaCTool.CLOUDFORMATION:
            if not self.config.stack_name:
                raise ValueError("stack_name is required for CloudFormation scans")
            return self.config.stack_name
        if self.config.iac_tool == IaCTool.PULUMI:
            if not self.config.pulumi_stack:
                raise ValueError("pulumi_stack is required for Pulumi scans")
            return self.config.pulumi_stack
        raise ValueError(f"Unknown IaC tool: {self.config.iac_tool}")

    @staticmethod
    def _build_parser(config: DriftFinderConfig) -> BaseParser:
        region = config.aws_region
        if config.iac_tool == IaCTool.TERRAFORM:
            return TerraformParser(region=region)
        if config.iac_tool == IaCTool.CLOUDFORMATION:
            return CloudFormationParser(region=region, profile=config.aws_profile)
        if config.iac_tool == IaCTool.PULUMI:
            return PulumiParser(region=region)
        raise ValueError(f"Unknown IaC tool: {config.iac_tool}")
