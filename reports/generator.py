"""
reports/generator.py

Renders a self-contained HTML report from data already stored in SQLite
(database/repository.get_scan_detail). This function only ever receives
data that was actually observed and stored during a real scan -- it does
not invent or estimate anything.
"""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def generate_html_report(scan_detail: dict, output_path: Path) -> Path:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # autoescape=True is forced unconditionally rather than using
        # jinja2.select_autoescape(["html"]), which decides based on the
        # TEMPLATE FILENAME's extension. Our template is named
        # "report.html.j2" (ends in .j2, not .html), so select_autoescape
        # would silently return False and NOT escape tool-provided values
        # like hostnames or emails before inserting them into the page --
        # this was caught by test_report_escapes_html_in_finding_values
        # and is exactly why that test exists. Since this project only
        # ever renders HTML, forcing autoescape=True avoids relying on a
        # filename heuristic at all.
        autoescape=True,
    )
    template = env.get_template("report.html.j2")

    # metadata_json / evidence_finding_ids are stored as JSON strings in
    # SQLite; decode them here so the template can iterate cleanly.
    for finding in scan_detail.get("findings", []):
        try:
            finding["metadata"] = json.loads(finding.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            finding["metadata"] = {}

    html = template.render(
        scan=scan_detail.get("scan", {}),
        plugin_runs=scan_detail.get("plugin_runs", []),
        findings=scan_detail.get("findings", []),
        alerts=scan_detail.get("alerts", []),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
