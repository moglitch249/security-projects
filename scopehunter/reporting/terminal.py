"""
terminal.py — Live Rich terminal output for scan progress and findings.
"""

from __future__ import annotations

from datetime import datetime

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from scopehunter.core.evidence import (
    Confidence,
    Finding,
    Severity,
    TechDetection,
    EndpointInfo,
)

console = Console(highlight=False)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim white",
}

_CONFIDENCE_ICONS: dict[Confidence, str] = {
    Confidence.HIGH: "●",
    Confidence.MEDIUM: "◑",
    Confidence.LOW: "○",
}


def print_banner() -> None:
    """Print the ScopeHunter banner."""
    banner = Text()
    banner.append("  ____                    _   _             _\n", style="bold cyan")
    banner.append(" / ___|  ___ ___  _ __   ___| | | _   _ _ __ | |_ ___ _ __\n", style="bold cyan")
    banner.append(" \\___ \\ / __/ _ \\| '_ \\ / _ \\ |_| | | | '_ \\| __/ _ \\ '__|\n", style="bold cyan")
    banner.append("  ___) | (_| (_) | |_) |  __/  _  | |_| | | | ||  __/ |\n", style="bold cyan")
    banner.append(" |____/ \\___\\___/| .__/ \\___|_| |_|\\__,_|_| |_|\\__\\___|_|\n", style="bold cyan")
    banner.append("                 |_|\n", style="bold cyan")

    panel = Panel(
        banner,
        subtitle="[dim]Technology-Aware Security Assessment Assistant[/dim]",
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(panel)
    console.print(
        f"  [dim]v0.1.0  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  "
        f"For authorized testing only[/dim]\n"
    )


def make_progress() -> Progress:
    """Create a Rich progress bar for scan stages."""
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=35, complete_style="cyan", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_tech_detections(detections: list[TechDetection]) -> None:
    """Print technology detection results as a rich table."""
    table = Table(
        title="Technology Detection",
        box=box.SIMPLE_HEAD,
        title_style="bold cyan",
        header_style="bold dim",
        border_style="dim",
    )
    table.add_column("Technology", style="bold white", min_width=20)
    table.add_column("Confidence", justify="right")
    table.add_column("Version", style="dim")
    table.add_column("Signals", style="dim", max_width=50)

    for d in detections:
        pct = int(d.confidence * 100)
        if pct >= 80:
            color = "green"
            icon = "✓"
        elif pct >= 50:
            color = "yellow"
            icon = "~"
        else:
            color = "dim"
            icon = "?"

        table.add_row(
            f"[{color}]{icon}[/{color}] {d.technology}",
            f"[{color}]{pct}%[/{color}]",
            d.version or "—",
            ", ".join(d.evidence[:2]) + ("..." if len(d.evidence) > 2 else ""),
        )

    console.print()
    console.print(table)


def print_attack_surface(endpoints: list[EndpointInfo]) -> None:
    """Print attack surface summary."""
    total = len(endpoints)
    methods: dict[str, int] = {}
    sources: dict[str, int] = {}
    id_endpoints = 0

    for ep in endpoints:
        methods[ep.method] = methods.get(ep.method, 0) + 1
        sources[ep.source] = sources.get(ep.source, 0) + 1
        if ep.has_object_identifiers:
            id_endpoints += 1

    # Summary panel
    summary = (
        f"  [bold white]Endpoints:[/bold white]          [cyan]{total}[/cyan]\n"
        f"  [bold white]With Object IDs:[/bold white]    [yellow]{id_endpoints}[/yellow]\n"
        f"  [bold white]Methods:[/bold white]            [dim]{', '.join(f'{k}:{v}' for k, v in methods.items())}[/dim]\n"
        f"  [bold white]Sources:[/bold white]            [dim]{', '.join(f'{k}:{v}' for k, v in list(sources.items())[:4])}[/dim]"
    )
    console.print()
    console.print(Panel(summary, title="[bold cyan]Attack Surface[/bold cyan]", border_style="cyan"))


def print_finding(finding: Finding) -> None:
    """Print a single finding with full detail."""
    color = _SEVERITY_COLORS.get(finding.severity, "white")
    conf_icon = _CONFIDENCE_ICONS.get(finding.confidence, "?")
    conf_color = {"high": "green", "medium": "yellow", "low": "dim"}.get(finding.confidence.value, "white")

    header = (
        f"[{color}][{finding.severity.value.upper()}][/{color}] "
        f"{finding.title}  "
        f"[{conf_color}]{conf_icon} {finding.confidence.value.capitalize()} Confidence[/{conf_color}]"
    )

    body = (
        f"[bold]Endpoint:[/bold]  {finding.method} {finding.endpoint}\n"
        f"[bold]Class:[/bold]     {finding.vuln_class.value}\n"
    )
    if finding.parameter:
        body += f"[bold]Parameter:[/bold] {finding.parameter}\n"
    if finding.technology:
        body += f"[bold]Technology:[/bold] {finding.technology}\n"

    body += f"\n[bold]Description:[/bold]\n{finding.description}\n"
    body += f"\n[bold]Why it matters:[/bold]\n[dim]{finding.why_it_matters}[/dim]\n"
    body += f"\n[bold]Manual Verification:[/bold]\n[dim]{finding.manual_verification}[/dim]\n"
    body += f"\n[bold]Remediation:[/bold]\n[dim]{finding.remediation}[/dim]"

    if finding.evidence:
        ev = finding.evidence[0]
        body += f"\n\n[bold]Evidence:[/bold] HTTP {ev.status_code} | {ev.response_size}B | {ev.elapsed_ms:.0f}ms"

    console.print()
    console.print(Panel(body, title=header, border_style=color.split(" ")[-1], padding=(0, 1)))


def print_findings_summary(findings: list[Finding]) -> None:
    """Print grouped summary table of all findings."""
    if not findings:
        console.print("\n[green]✓ No findings detected.[/green]\n")
        return

    table = Table(
        title="Findings Summary",
        box=box.ROUNDED,
        title_style="bold",
        header_style="bold dim",
        border_style="dim",
    )
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Severity", min_width=10)
    table.add_column("Title", min_width=40)
    table.add_column("Endpoint", min_width=35)
    table.add_column("Confidence", justify="center")

    for i, f in enumerate(findings, 1):
        color = _SEVERITY_COLORS.get(f.severity, "white")
        conf_icon = _CONFIDENCE_ICONS.get(f.confidence, "?")
        table.add_row(
            str(i),
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.title[:55],
            f.endpoint[:45],
            f"[dim]{conf_icon}[/dim] {f.confidence.value}",
        )

    console.print()
    console.print(table)


def print_cves(cves: list[dict]) -> None:
    """Print potentially applicable CVEs for manual review."""
    if not cves:
        return

    table = Table(
        title="Potentially Applicable CVEs (Manual Verification Required)",
        box=box.SIMPLE_HEAD,
        title_style="bold yellow",
        header_style="bold dim",
        border_style="yellow",
    )
    table.add_column("CVE ID", style="yellow bold", min_width=16)
    table.add_column("Component", min_width=20)
    table.add_column("Affected", min_width=15)
    table.add_column("Detected", min_width=12)
    table.add_column("Status")

    for cve in cves:
        version_confirmed = cve.get("version_confirmed", False)
        detected = cve.get("detected_version") or "Unknown"
        status = (
            "[red]Version match[/red]" if version_confirmed
            else "[dim]Version unknown[/dim]"
        )
        table.add_row(
            cve["id"],
            cve["component"],
            cve["affected_versions"],
            detected,
            status,
        )

    console.print()
    console.print(table)
    console.print(
        "  [dim][!] CVEs listed for awareness only. "
        "Manual verification required. Do NOT exploit.[/dim]\n"
    )


def print_scan_complete(stats: dict) -> None:
    """Print final scan statistics."""
    sev = stats.get("findings_by_severity", {})
    summary = (
        f"  [bold white]Endpoints Discovered:[/bold white]   [cyan]{stats.get('endpoints_discovered', 0)}[/cyan]\n"
        f"  [bold white]Technologies Detected:[/bold white]  [cyan]{stats.get('technologies_detected', 0)}[/cyan]\n"
        f"  [bold white]Total Findings:[/bold white]        [bold]{stats.get('findings_total', 0)}[/bold]\n"
        f"  [red]Critical:[/red] {sev.get('critical', 0)}  "
        f"[red]High:[/red] {sev.get('high', 0)}  "
        f"[yellow]Medium:[/yellow] {sev.get('medium', 0)}  "
        f"[cyan]Low:[/cyan] {sev.get('low', 0)}  "
        f"[dim]Info:[/dim] {sev.get('informational', 0)}\n"
        f"  [bold white]Applicable CVEs:[/bold white]       [yellow]{stats.get('applicable_cves', 0)}[/yellow]"
    )
    console.print()
    console.print(Panel(
        summary,
        title="[bold green]✓ Scan Complete[/bold green]",
        border_style="green",
    ))
