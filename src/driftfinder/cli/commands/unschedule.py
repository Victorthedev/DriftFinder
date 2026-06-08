import sys

import click

from driftfinder.scheduler.cron import CronScheduler


@click.command("unschedule")
def unschedule_command() -> None:
    """Remove the DriftFinder crontab entry."""
    scheduler = CronScheduler()
    current = scheduler.show()

    if not current:
        click.echo("No DriftFinder scheduled scan found.")
        return

    try:
        scheduler.unschedule()
    except NotImplementedError as exc:
        click.secho(str(exc), fg="yellow", err=True)
        sys.exit(2)
    except RuntimeError as exc:
        click.secho(str(exc), fg="red", err=True)
        sys.exit(2)

    click.secho("Scheduled scan removed.", fg="green")
