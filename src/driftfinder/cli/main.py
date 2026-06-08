import click

from driftfinder import __version__
from driftfinder.cli.commands import (
    init_command,
    report_command,
    scan_command,
    schedule_command,
    unschedule_command,
)


@click.group()
@click.version_option(version=__version__, prog_name="driftfinder")
def cli() -> None:
    """DriftFinder — open source IaC compliance drift detection.

    Detects drift between declared IaC state and live AWS runtime state,
    mapped to CIS AWS Foundations Benchmark v3.0 controls.
    """


cli.add_command(init_command, name="init")
cli.add_command(scan_command, name="scan")
cli.add_command(schedule_command, name="schedule")
cli.add_command(unschedule_command, name="unschedule")
cli.add_command(report_command, name="report")
