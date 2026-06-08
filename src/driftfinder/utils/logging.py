import logging
import sys


def configure_logging(verbose: bool = False) -> None:
    """
    Configure root logger for DriftFinder CLI output.
    verbose=True sets DEBUG level; default is WARNING so normal scans are quiet.
    """
    level = logging.DEBUG if verbose else logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    root = logging.getLogger("driftfinder")
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a driftfinder-namespaced logger."""
    return logging.getLogger(f"driftfinder.{name}")
