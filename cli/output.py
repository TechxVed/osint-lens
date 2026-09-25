"""
cli/output.py

All Rich-specific rendering lives here, kept separate from
cli/commands.py so the command logic doesn't get tangled up with
presentation details. If we ever swapped Rich for something else, this
is the only file that would need to change.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.models import PluginResult, Finding, Alert, PluginStatus

console = Console()

_STATUS_STYLE = {
    PluginStatus.SUCCESS: "green",
    PluginStatus.FAILED: "red",
    PluginStatus.TIMEOUT: "yellow",
    PluginStatus.SKIPPED: "dim",
}


def print_plugin_results(results: list[PluginResult]) -> None:
    table = Table(title="Module Execution")
    table.add_column("Plugin")
    table.add_column("Status")
    table.add_column("Duration (s)", justify="right")
    table.add_column("Notes")

    for r in results:
        style = _STATUS_STYLE.get(r.status, "white")
        table.add_row(
            r.plugin_name,
            f"[{style}]{r.status.value}[/{style}]",
            f"{r.duration_seconds:.2f}",
            r.error_message or "",
        )
    console.print(table)


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[dim]No findings.[/dim]")
        return
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Confidence", justify="right")

    for f in findings:
        table.add_row(f.source, f.data_type.value, f.value, f"{f.confidence:.2f}")
    console.print(table)


def print_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        console.print("[dim]No correlation alerts fired.[/dim]")
        return
    for a in alerts:
        console.print(Panel(
            f"[bold]{a.description}[/bold]\n\n{a.rationale}",
            title=f"[yellow]Alert: {a.rule_name}[/yellow]",
            border_style="yellow",
        ))


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_info(message: str) -> None:
    console.print(f"[cyan]{message}[/cyan]")
