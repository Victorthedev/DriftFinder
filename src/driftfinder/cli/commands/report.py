import json
import sys
from pathlib import Path

import click

from driftfinder.models.findings import ScanResult
from driftfinder.reporters.html_reporter import write_html
from driftfinder.reporters.json_reporter import write_json


@click.command("report")
@click.option("--input", "input_path", required=True, help="Path to a previous JSON scan result.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "html", "both"]),
    default="html",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    help="Output path prefix (without extension). Defaults to input path stem.",
)
def report_command(input_path: str, output_format: str, output_path: str | None) -> None:
    """Re-render a previous JSON scan result in the requested format."""
    src = Path(input_path)
    if not src.exists():
        click.secho(f"File not found: {input_path}", fg="red", err=True)
        sys.exit(2)

    try:
        data = json.loads(src.read_text(encoding="utf-8"))
        result = ScanResult.model_validate(data)
    except Exception as exc:
        click.secho(f"Failed to parse scan result: {exc}", fg="red", err=True)
        sys.exit(2)

    base = output_path or str(src.with_suffix(""))

    if output_format in ("json", "both"):
        write_json(result, f"{base}.json")
        click.echo(f"JSON report: {base}.json")

    if output_format in ("html", "both"):
        write_html(result, f"{base}.html")
        click.echo(f"HTML report: {base}.html")
