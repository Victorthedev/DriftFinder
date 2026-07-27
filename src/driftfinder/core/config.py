import yaml
from pydantic import BaseModel, model_validator

from driftfinder.models.enums import FailOn, IaCTool, OutputFormat, ScanMode

CONFIG_FILE_NAME = ".driftfinder.yml"


class DriftFinderConfig(BaseModel):
    # Required
    iac_tool: IaCTool
    aws_profile: str | None = None
    aws_region: str = "eu-west-1"

    # IaC source — exactly one must be set per iac_tool
    state_file: str | None = None  # Terraform: local path or s3://...
    stack_name: str | None = None  # CloudFormation: stack name
    pulumi_stack: str | None = None  # Pulumi: stack export JSON path

    # Scan options
    output_format: OutputFormat = OutputFormat.BOTH
    output_path: str | None = None
    fail_on: FailOn = FailOn.CRITICAL
    mode: ScanMode = ScanMode.DEFAULT

    # Retry config (passed through to @aws_retry-decorated queriers)
    max_retries: int = 3
    retry_base_delay: float = 1.0
    retry_max_delay: float = 30.0

    @model_validator(mode="after")
    def at_least_one_source(self) -> "DriftFinderConfig":
        if not any([self.state_file, self.stack_name, self.pulumi_stack]):
            raise ValueError(
                "At least one state source must be configured: "
                "state_file, stack_name or pulumi_stack"
            )
        return self

    @classmethod
    def from_file(cls, path: str = CONFIG_FILE_NAME) -> "DriftFinderConfig":
        with open(path) as fh:
            data = yaml.safe_load(fh)
        return cls(**(data or {}))

    @classmethod
    def from_env(cls) -> "DriftFinderConfig":
        import os

        return cls(
            iac_tool=os.environ["DRIFTFINDER_TOOL"],
            aws_region=os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"),
            aws_profile=os.environ.get("DRIFTFINDER_AWS_PROFILE"),
            state_file=os.environ.get("DRIFTFINDER_STATE_FILE"),
            stack_name=os.environ.get("DRIFTFINDER_STACK_NAME"),
            pulumi_stack=os.environ.get("DRIFTFINDER_PULUMI_STACK"),
        )
