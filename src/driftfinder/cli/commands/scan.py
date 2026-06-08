import sys
from pathlib import Path

import click

from driftfinder.core.config import CONFIG_FILE_NAME, DriftFinderConfig
from driftfinder.core.engine import DriftFinderEngine
from driftfinder.models.enums import FailOn, IaCTool, OutputFormat, ScanMode, Severity
from driftfinder.reporters.html_reporter import write_html
from driftfinder.reporters.json_reporter import write_json
from driftfinder.utils.logging import configure_logging

_SEVERITY_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
_FAIL_ON_ORDER = {FailOn.CRITICAL: 4, FailOn.HIGH: 3, FailOn.MEDIUM: 2, FailOn.LOW: 1}
_BADGE_COLOURS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "blue",
    Severity.LOW: "white",
}


def _exceeds_threshold(severity: Severity, fail_on: FailOn) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _FAIL_ON_ORDER.get(fail_on, 4)


def _print_summary(result) -> None:  # type: ignore[type-arg]
    click.echo("")
    click.echo(f"  Resources scanned  : {result.resources_scanned}")
    click.echo(f"  Resources with drift: {result.resources_with_drift}")
    click.echo(
        f"  Findings           : {len(result.findings)}"
        f"  (CRITICAL={result.critical_count}"
        f" HIGH={result.high_count}"
        f" MEDIUM={result.medium_count}"
        f" LOW={result.low_count})"
    )
    click.echo(f"  Duration           : {result.scan_duration_seconds}s")
    click.echo("")

    if not result.findings:
        click.secho("  No drift detected. All resources comply.", fg="green")
        click.echo("")
        return

    rows = sorted(
        result.findings,
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )
    click.echo(f"  {'SEV':<10} {'RESOURCE':<22} {'PROPERTY':<36} {'DECLARED':<18} ACTUAL")
    click.echo("  " + "-" * 104)
    for f in rows:
        colour = _BADGE_COLOURS.get(f.severity, "white")
        sev = click.style(f"{f.severity:<10}", fg=colour, bold=True)
        resource = f"{f.resource_id[:20]:<22}"
        prop = f"{f.property_path[:34]:<36}"
        declared = f"{str(f.declared_value)[:16]:<18}"
        actual = str(f.actual_value)[:24]
        click.echo(f"  {sev} {resource} {prop} {declared} {actual}")
    click.echo("")


@click.command("scan")
@click.option(
    "--config", "config_path", default=CONFIG_FILE_NAME, show_default=True, help="Config file path."
)
@click.option(
    "--tool", type=click.Choice([t.value for t in IaCTool]), default=None, help="Override IaC tool."
)
@click.option("--state", default=None, help="Override Terraform state file path.")
@click.option("--stack", default=None, help="Override CloudFormation stack name.")
@click.option(
    "--output", "output_path", default=None, help="Output path prefix (without extension)."
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "html", "both"]),
    default=None,
    help="Output format.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailOn]),
    default=None,
    help="Severity threshold for non-zero exit.",
)
@click.option(
    "--mode",
    type=click.Choice(["default", "report-only"]),
    default=None,
    help="report-only mode never exits with code 1.",
)
@click.option("--profile", default=None, help="AWS credentials profile.")
@click.option("--region", default=None, help="AWS region.")
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging.")
def scan_command(
    config_path: str,
    tool: str | None,
    state: str | None,
    stack: str | None,
    output_path: str | None,
    output_format: str | None,
    fail_on: str | None,
    mode: str | None,
    profile: str | None,
    region: str | None,
    verbose: bool,
) -> None:
    """Run a drift detection scan against live AWS state.

    Exit codes: 0=compliant, 1=drift found at or above --fail-on severity, 2=error.
    """
    configure_logging(verbose=verbose)

    try:
        if Path(config_path).exists():
            config = DriftFinderConfig.from_file(config_path)
        else:
            if not tool:
                raise click.UsageError(
                    f"No config file at '{config_path}' and --tool not provided. "
                    "Run 'driftfinder init' to create a config."
                )
            config = DriftFinderConfig(iac_tool=IaCTool(tool), state_file=state, stack_name=stack)
    except click.UsageError:
        raise
    except Exception as exc:
        click.secho(f"Config error: {exc}", fg="red", err=True)
        sys.exit(2)

    overrides: dict = {}
    if tool:
        overrides["iac_tool"] = IaCTool(tool)
    if state:
        overrides["state_file"] = state
    if stack:
        overrides["stack_name"] = stack
    if output_path:
        overrides["output_path"] = output_path
    if output_format:
        overrides["output_format"] = OutputFormat(output_format)
    if fail_on:
        overrides["fail_on"] = FailOn(fail_on)
    if mode:
        overrides["mode"] = ScanMode.REPORT_ONLY if mode == "report-only" else ScanMode.DEFAULT
    if profile:
        overrides["aws_profile"] = profile
    if region:
        overrides["aws_region"] = region

    if overrides:
        try:
            config = config.model_copy(update=overrides)
        except Exception as exc:
            click.secho(f"Invalid option: {exc}", fg="red", err=True)
            sys.exit(2)

    try:
        engine = DriftFinderEngine(config)
        result = engine.scan()
    except Exception as exc:
        click.secho(f"Scan error: {exc}", fg="red", err=True)
        sys.exit(2)

    _print_summary(result)

    base = config.output_path or "drift-report"
    fmt = config.output_format

    if fmt in (OutputFormat.JSON, OutputFormat.BOTH):
        write_json(result, f"{base}.json")
        click.echo(f"  JSON report: {base}.json")

    if fmt in (OutputFormat.HTML, OutputFormat.BOTH):
        write_html(result, f"{base}.html")
        click.echo(f"  HTML report: {base}.html")

    if config.mode == ScanMode.REPORT_ONLY:
        sys.exit(0)

    has_blocking = any(_exceeds_threshold(f.severity, config.fail_on) for f in result.findings)
    sys.exit(1 if has_blocking else 0)
