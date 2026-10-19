import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from driftfinder.cli.commands.scan import scan_command
from driftfinder.models.findings import ScanError, ScanResult


def _result(errors):
    return ScanResult(
        findings=[],
        scan_timestamp=datetime.now(tz=UTC),
        iac_tool="terraform",
        state_source="terraform.tfstate",
        resources_scanned=1,
        resources_with_drift=0,
        compliant=not errors,
        scan_duration_seconds=0.1,
        scan_errors=errors,
    )


def _invoke(tmp_path, monkeypatch, result, *extra):
    config = tmp_path / ".driftfinder.yml"
    config.write_text("iac_tool: terraform\nstate_file: terraform.tfstate\noutput_format: json\n")
    monkeypatch.setattr(
        "driftfinder.cli.commands.scan.DriftFinderEngine",
        lambda cfg: SimpleNamespace(scan=lambda: result),
    )
    output = tmp_path / "report"
    run = CliRunner().invoke(
        scan_command, ["--config", str(config), "--output", str(output), *extra]
    )
    return run, output.with_suffix(".json")


ERROR = ScanError(resource_type="NRMS3Bucket", resource_id="my-bucket", error="AccessDenied")


@pytest.mark.parametrize("mode", [[], ["--mode", "report-only"]])
def test_incomplete_scan_exits_with_error_and_writes_report(tmp_path, monkeypatch, mode):
    run, report = _invoke(tmp_path, monkeypatch, _result([ERROR]), *mode)
    assert run.exit_code == 2
    assert "could not be checked" in run.output
    assert "All resources comply" not in run.output
    saved = json.loads(report.read_text())
    assert saved["compliant"] is False
    assert saved["scan_errors"][0]["resource_id"] == "my-bucket"


def test_complete_clean_scan_exits_zero(tmp_path, monkeypatch):
    run, report = _invoke(tmp_path, monkeypatch, _result([]))
    assert run.exit_code == 0
    assert "All resources comply" in run.output
    assert json.loads(report.read_text())["scan_errors"] == []
