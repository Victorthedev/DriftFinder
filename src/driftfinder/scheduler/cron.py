import logging
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)

_CRON_COMMENT = "# DriftFinder scheduled scan"


def _cron_expression(interval_minutes: int) -> str:
    if interval_minutes == 1:
        return "* * * * *"
    if interval_minutes < 60:
        return f"*/{interval_minutes} * * * *"
    if interval_minutes == 60:
        return "0 * * * *"
    hours = interval_minutes // 60
    return f"0 */{hours} * * *"


def _read_crontab() -> str:
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)  # noqa: S607
    return result.stdout if result.returncode == 0 else ""


def _write_crontab(content: str) -> None:
    result = subprocess.run(
        ["crontab", "-"],  # noqa: S607
        input=content,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to write crontab: {result.stderr}")


class CronScheduler:
    """
    Manages crontab entries for scheduled DriftFinder scans.

    On Windows, crontab is not available — callers should handle the
    NotImplementedError and direct users to Task Scheduler instead.
    """

    def schedule(
        self,
        interval_minutes: int,
        config_path: str,
        output_path: str,
    ) -> None:
        if sys.platform == "win32":
            raise NotImplementedError(
                "Cron scheduling is not supported on Windows. "
                "Use Task Scheduler and run: driftfinder scan --config <path>"
            )

        binary = shutil.which("driftfinder")
        if not binary:
            raise RuntimeError(
                "driftfinder binary not found in PATH. "
                "Run 'pip install driftfinder' or activate the correct virtual environment."
            )

        cron_expr = _cron_expression(interval_minutes)
        command = (
            f"{binary} scan"
            f" --config {config_path}"
            f" --output {output_path}"
            f" --mode report-only"
        )
        cron_line = f"{cron_expr} {command} {_CRON_COMMENT}"

        current = _read_crontab()
        lines = [ln for ln in current.splitlines() if _CRON_COMMENT not in ln]
        lines.append(cron_line)
        _write_crontab("\n".join(lines) + "\n")
        logger.info("Scheduled DriftFinder scan: %s", cron_line)

    def unschedule(self) -> None:
        if sys.platform == "win32":
            raise NotImplementedError("Cron scheduling is not supported on Windows.")

        current = _read_crontab()
        lines = [ln for ln in current.splitlines() if _CRON_COMMENT not in ln]
        _write_crontab("\n".join(lines) + "\n")
        logger.info("Removed DriftFinder crontab entry.")

    def show(self) -> str | None:
        """Return the current DriftFinder crontab line, or None if not scheduled."""
        if sys.platform == "win32":
            return None
        current = _read_crontab()
        for line in current.splitlines():
            if _CRON_COMMENT in line:
                return line
        return None
