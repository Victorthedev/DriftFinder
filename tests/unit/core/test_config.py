import pytest

from driftfinder.core.config import DriftFinderConfig
from driftfinder.models.enums import FailOn, IaCTool, OutputFormat, ScanMode


class TestDriftFinderConfig:
    def test_minimal_terraform_config(self):
        cfg = DriftFinderConfig(iac_tool=IaCTool.TERRAFORM, state_file="tf.tfstate")
        assert cfg.aws_region == "eu-west-1"
        assert cfg.fail_on == FailOn.CRITICAL
        assert cfg.output_format == OutputFormat.BOTH

    def test_minimal_cloudformation_config(self):
        cfg = DriftFinderConfig(iac_tool=IaCTool.CLOUDFORMATION, stack_name="my-stack")
        assert cfg.stack_name == "my-stack"

    def test_minimal_pulumi_config(self):
        cfg = DriftFinderConfig(iac_tool=IaCTool.PULUMI, pulumi_stack="stack.json")
        assert cfg.pulumi_stack == "stack.json"

    def test_missing_source_raises(self):
        with pytest.raises(Exception, match="state source"):
            DriftFinderConfig(iac_tool=IaCTool.TERRAFORM)

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("DRIFTFINDER_TOOL", "terraform")
        monkeypatch.setenv("DRIFTFINDER_STATE_FILE", "terraform.tfstate")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        cfg = DriftFinderConfig.from_env()
        assert cfg.iac_tool == IaCTool.TERRAFORM
        assert cfg.aws_region == "us-east-1"

    def test_from_file(self, tmp_path):
        config_file = tmp_path / ".driftfinder.yml"
        config_file.write_text(
            "iac_tool: terraform\nstate_file: terraform.tfstate\naws_region: eu-west-1\n"
        )
        cfg = DriftFinderConfig.from_file(str(config_file))
        assert cfg.iac_tool == IaCTool.TERRAFORM
        assert cfg.state_file == "terraform.tfstate"

    def test_model_copy_with_override(self):
        cfg = DriftFinderConfig(iac_tool=IaCTool.TERRAFORM, state_file="tf.tfstate")
        updated = cfg.model_copy(update={"aws_region": "us-west-2"})
        assert updated.aws_region == "us-west-2"
        assert cfg.aws_region == "eu-west-1"

    def test_report_only_mode(self):
        cfg = DriftFinderConfig(
            iac_tool=IaCTool.TERRAFORM,
            state_file="tf.tfstate",
            mode=ScanMode.REPORT_ONLY,
        )
        assert cfg.mode == ScanMode.REPORT_ONLY
