import json
import logging
from pathlib import Path

from driftfinder.models.findings import ScanResult

logger = logging.getLogger(__name__)


def write_json(result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logger.info("JSON report written to %s", path)


def as_json_string(result: ScanResult) -> str:
    payload = result.model_dump(mode="json")
    return json.dumps(payload, indent=2, default=str)
