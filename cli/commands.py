"""
cli/commands.py

Defines every CLI command. Typer inspects each function's signature
(parameter names, type hints, default values) and generates the
argument parser, --help text, and type validation from it -- you write
plain Python functions, not parser configuration.
"""

from pathlib import Path

import typer

from core.exceptions import TargetValidationError, OsintLensError
from core.validators import validate_target, confirm_authorization
from core.registry import get_plugin_classes, list_available_plugins
from core.orchestrator import run_scan
from core.normalizer import normalize_findings
from core.correlator import run_correlation
from database.connection import get_connection, init_db
from database import repository
from reports.generator import generate_html_report
from cli import output

app = typer.Typer(help="OSINT-Lens: a single-terminal OSINT aggregation and correlation tool.")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Domain or IP address to scan."),
    modules: str = typer.Option(
        "mock_example", "--modules",
        help="Comma-separated plugin names, e.g. mock_example,shodan"
    ),
    yes: bool = typer.Option(
        False, "--yes",
        help="Skip the interactive authorization prompt "
             "(use only in scripted/CI contexts where authorization was "
             "already separately confirmed)."
    ),
    report: bool = typer.Option(
        False, "--report", help="Generate an HTML report after the scan."
    ),
):
    """Run OSINT modules against TARGET and display results."""
    try:
        clean_target = validate_target(target)
    except TargetValidationError as e:
        output.print_error(str(e))
        raise typer.Exit(code=1)

    if not confirm_authorization(clean_target, assume_yes=yes):
        output.print_error("Authorization not confirmed. Aborting scan.")
        raise typer.Exit(code=1)

    module_names = [m.strip() for m in modules.split(",") if m.strip()]
    try:
        plugin_classes = get_plugin_classes(module_names)
    except KeyError as e:
        output.print_error(str(e))
        raise typer.Exit(code=1)

    plugin_instances = [cls() for cls in plugin_classes]

    output.print_info(f"Running {len(plugin_instances)} module(s) against {clean_target}...")
    plugin_results = run_scan(clean_target, plugin_instances)
    output.print_plugin_results(plugin_results)

    all_findings = [f for r in plugin_results for f in r.findings]
    normalized = normalize_findings(all_findings)
    output.print_findings(normalized)

    alerts = run_correlation(normalized, clean_target)
    output.print_alerts(alerts)

    init_db()
    conn = get_connection()
    try:
        scan_id = repository.create_scan(conn, clean_target, module_names)
        for r in plugin_results:
            repository.save_plugin_result(conn, scan_id, r)
        finding_id_map = repository.save_findings(conn, scan_id, normalized)
        repository.save_alerts(conn, scan_id, alerts, finding_id_map)
    finally:
        conn.close()

    output.print_info(f"Scan saved (scan_id={scan_id}). Run 'history' to view past scans.")

    if report:
        _generate_report_for_scan(scan_id)


@app.command()
def modules():
    """List available plugins and whether they're currently usable."""
    plugins = list_available_plugins()
    for p in plugins:
        status = "[green]available[/green]" if p["available"] else "[dim]unavailable[/dim]"
        output.console.print(f"[bold]{p['key']}[/bold] ({status}): {p['description']}")


@app.command()
def history(limit: int = typer.Option(10, help="Number of recent scans to show.")):
    """Show recent scan history."""
    init_db()
    conn = get_connection()
    try:
        rows = repository.get_recent_scans(conn, limit=limit)
    finally:
        conn.close()
    if not rows:
        output.print_info("No scans recorded yet.")
        return
    for row in rows:
        output.console.print(
            f"[bold]#{row['id']}[/bold]  {row['target']}  "
            f"({row['modules_requested']})  {row['started_at']}"
        )


@app.command()
def report(scan_id: int = typer.Argument(..., help="Scan ID from 'history'.")):
    """Generate an HTML report for a previously run scan."""
    _generate_report_for_scan(scan_id)


def _generate_report_for_scan(scan_id: int) -> None:
    conn = get_connection()
    try:
        detail = repository.get_scan_detail(conn, scan_id)
    finally:
        conn.close()
    if not detail:
        output.print_error(f"No scan found with id {scan_id}.")
        raise typer.Exit(code=1)

    out_path = Path("data") / f"report_scan_{scan_id}.html"
    generate_html_report(detail, out_path)
    output.print_info(f"Report written to {out_path}")


@app.command()
def version():
    """Print the tool version."""
    output.console.print("OSINT-Lens v0.1.0")
