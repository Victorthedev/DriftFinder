import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from driftfinder.models.findings import ScanResult

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "report.html.j2"


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )


def write_html(result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result)
    path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", path)


def render_html(result: ScanResult) -> str:
    env = _get_env()
    template = env.get_template(_TEMPLATE_NAME)
    return template.render(result=result, version="1.0.0")
