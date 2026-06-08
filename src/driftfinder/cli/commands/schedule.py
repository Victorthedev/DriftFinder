import sys

import click

from driftfinder.core.config import CONFIG_FILE_NAME
from driftfinder.scheduler.cron import CronScheduler


def _parse_interval(interval: str) -> int:
    """Convert interval string (15m, 1h, 1d) to minutes."""
    interval = interval.strip().lower()
    if interval.endswith("d"):
        return int(interval[:-1]) * 1440
    if interval.endswith("h"):
        return int(interval[:-1]) * 60
    if interval.endswith("m"):
        return int(interval[:-1])
    raise click.BadParameter(
        f"Unrecognised interval '{interval}'. Use formats like 15m, 1h, 6h, 1d."
    )


@click.command("schedule")
@click.option(
    "--interval", default="15m", show_default=True, help="Scan interval: 15m, 30m, 1h, 6h, 1d."
)
@click.option(
    "--config",
    "config_path",
    default=CONFIG_FILE_NAME,
    show_default=True,
    help="Config file to use in scheduled scans.",
)
@click.option(
    "--output",
    "output_path",
    default="./drift-reports",
    show_default=True,
    help="Directory for scan output files.",
)
def schedule_command(interval: str, config_path: str, output_path: str) -> None:
    """Create a crontab entry that runs drift scans on a schedule."""
    try:
        minutes = _parse_interval(interval)
    except (ValueError, click.BadParameter) as exc:
        click.secho(str(exc), fg="red", err=True)
        sys.exit(2)

    try:
        scheduler = CronScheduler()
        scheduler.schedule(minutes, config_path, output_path)
    except NotImplementedError as exc:
        click.secho(str(exc), fg="yellow", err=True)
        sys.exit(2)
    except RuntimeError as exc:
        click.secho(str(exc), fg="red", err=True)
        sys.exit(2)

    click.secho(
        f"Scheduled: every {interval} — output to {output_path}",
        fg="green",
    )
    click.echo("Scheduled scans run in report-only mode and never fail the cron job.")
    current = CronScheduler().show()
    if current:
        click.echo(f"Crontab entry: {current}")
