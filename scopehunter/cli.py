"""
cli.py — ScopeHunter interactive CLI entrypoint.

Interactive TUI using Questionary + Rich.
CLI flags using Click.

Usage:
    scopehunter                                          # Interactive mode
    scopehunter --target https://example.com            # Auto detect
    scopehunter --technology wordpress --target URL
    scopehunter --check access-control --target URL
    scopehunter --report html --target URL
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click
import questionary
from questionary import Style as QStyle
from rich.console import Console

from scopehunter.core.evidence import SessionProfile
from scopehunter.engine.orchestrator import Orchestrator, ScanConfig, ScanResult
from scopehunter import __version__

console = Console()

# ---------------------------------------------------------------------------
# Questionary styling
# ---------------------------------------------------------------------------
_Q_STYLE = QStyle([
    ("qmark",        "fg:#58a6ff bold"),
    ("question",     "bold"),
    ("answer",       "fg:#58a6ff bold"),
    ("pointer",      "fg:#58a6ff bold"),
    ("highlighted",  "fg:#58a6ff bold"),
    ("selected",     "fg:#3fb950"),
    ("separator",    "fg:#30363d"),
    ("instruction",  "fg:#8b949e"),
    ("text",         ""),
    ("disabled",     "fg:#8b949e italic"),
])

_TECHNOLOGY_CHOICES = [
    "Auto Detect",
    "WordPress",
    "Laravel",
    "Django",
    "Express.js",
    "Next.js",
    "Generic Web Application",
]

_PROFILE_CHOICES = [
    questionary.Choice("Recon Only",           value="recon"),
    questionary.Choice("Endpoint Discovery",    value="endpoint"),
    questionary.Choice("Access Control",        value="access_control"),
    questionary.Choice("Information Disclosure",value="disclosure"),
    questionary.Choice("Configuration Check",   value="configuration"),
    questionary.Choice("Full Safe Assessment",  value="full"),
]

# ---------------------------------------------------------------------------
# Configure logging
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Interactive session profile builder
# ---------------------------------------------------------------------------

def _collect_sessions() -> list[SessionProfile]:
    """Interactively collect session profiles from the user."""
    sessions: list[SessionProfile] = []

    add_session = questionary.confirm(
        "Add session profiles for authenticated testing? (BAC/IDOR checks)",
        default=False,
        style=_Q_STYLE,
    ).ask()

    if not add_session:
        return sessions

    while True:
        console.print("\n[cyan]Session Profile[/cyan]")
        name = questionary.text(
            "  Profile name (e.g. 'owner', 'another_user', 'admin'):",
            style=_Q_STYLE,
        ).ask()
        if not name:
            break

        auth_type = questionary.select(
            "  Authentication type:",
            choices=["Cookie", "Bearer Token", "Custom Header"],
            style=_Q_STYLE,
        ).ask()

        profile = SessionProfile(name=name)

        if auth_type == "Cookie":
            raw = questionary.text(
                "  Cookie string (e.g. session=abc123; token=xyz):",
                style=_Q_STYLE,
            ).ask() or ""
            for part in raw.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    profile.cookies[k.strip()] = v.strip()

        elif auth_type == "Bearer Token":
            token = questionary.text("  Bearer token:", style=_Q_STYLE).ask() or ""
            profile.bearer_token = token

        elif auth_type == "Custom Header":
            header = questionary.text("  Header name:", style=_Q_STYLE).ask() or ""
            value = questionary.text("  Header value:", style=_Q_STYLE).ask() or ""
            if header:
                profile.headers[header] = value

        sessions.append(profile)
        console.print(f"  [green]✓[/green] Session '{name}' added")

        add_more = questionary.confirm(
            "  Add another session?", default=False, style=_Q_STYLE
        ).ask()
        if not add_more:
            break

    return sessions


# ---------------------------------------------------------------------------
# Core scan runner
# ---------------------------------------------------------------------------

async def _run_scan(config: ScanConfig, report_formats: list[str], output_dir: Path) -> ScanResult:
    """Execute the scan and generate reports."""
    from scopehunter.reporting import terminal as term
    from scopehunter.reporting import json_report, html_report

    term.print_banner()

    # Progress tracking
    progress = term.make_progress()
    task_id = progress.add_task("Initializing...", total=100)

    def on_progress(stage: str, message: str, percent: float) -> None:
        progress.update(task_id, description=f"[cyan]{message}[/cyan]", completed=int(percent * 100))

    with progress:
        orch = Orchestrator(config, on_progress=on_progress)
        result = await orch.run()

    # Print detections
    term.print_tech_detections(result.detections)
    term.print_attack_surface(result.endpoints)
    term.print_cves(result.applicable_cves)

    # Print findings
    for finding in result.findings:
        term.print_finding(finding)

    term.print_findings_summary(result.findings)
    term.print_scan_complete(result.stats)

    # Generate file reports
    timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = config.target.replace("https://", "").replace("http://", "").replace("/", "_")[:40]
    base_name = f"scopehunter_{safe_target}_{timestamp}"

    if "json" in report_formats:
        out = output_dir / f"{base_name}.json"
        json_report.generate(result, out)
        console.print(f"\n  [dim]JSON report:[/dim] [cyan]{out}[/cyan]")

    if "html" in report_formats:
        out = output_dir / f"{base_name}.html"
        html_report.generate(result, out)
        console.print(f"  [dim]HTML report:[/dim] [cyan]{out}[/cyan]")

    return result


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def _run_interactive() -> None:
    """Launch the interactive questionary-based scan wizard."""
    from scopehunter.reporting.terminal import print_banner
    print_banner()

    console.print("[bold cyan]Interactive Scan Setup[/bold cyan]\n")

    # Target
    target = questionary.text(
        "Target URL:",
        validate=lambda v: v.startswith(("http://", "https://")) or "Must start with http:// or https://",
        style=_Q_STYLE,
    ).ask()
    if not target:
        sys.exit(0)

    # Scope
    scope_raw = questionary.text(
        "Allowed scope (comma-separated, e.g. '*.example.com,api.example.com'):",
        default="",
        style=_Q_STYLE,
    ).ask() or ""
    allowed_scope = [s.strip() for s in scope_raw.split(",") if s.strip()]

    # Technology
    tech_choice = questionary.select(
        "Select technology:",
        choices=_TECHNOLOGY_CHOICES,
        style=_Q_STYLE,
    ).ask()
    technology = None if tech_choice == "Auto Detect" else tech_choice
    if tech_choice == "Generic Web Application":
        technology = "generic"

    # Scan profile
    profile = questionary.select(
        "Select scan profile:",
        choices=_PROFILE_CHOICES,
        style=_Q_STYLE,
    ).ask() or "full"

    # Rate limit
    rate_str = questionary.text(
        "Max request rate (req/sec):",
        default="5",
        style=_Q_STYLE,
    ).ask() or "5"
    try:
        rate_limit = float(rate_str)
    except ValueError:
        rate_limit = 5.0

    # Sessions
    sessions = _collect_sessions()

    # Reports
    report_formats_raw = questionary.checkbox(
        "Report formats:",
        choices=[
            questionary.Choice("Terminal (live)", value="terminal", checked=True),
            questionary.Choice("JSON",            value="json",     checked=True),
            questionary.Choice("HTML",            value="html",     checked=True),
        ],
        style=_Q_STYLE,
    ).ask() or ["terminal"]

    # Output dir
    output_raw = questionary.text(
        "Output directory:",
        default="./scopehunter_reports",
        style=_Q_STYLE,
    ).ask() or "./scopehunter_reports"
    output_dir = Path(output_raw)

    # Confirm
    console.print("\n[bold]Scan Configuration:[/bold]")
    console.print(f"  Target:   [cyan]{target}[/cyan]")
    console.print(f"  Tech:     [cyan]{tech_choice}[/cyan]")
    console.print(f"  Profile:  [cyan]{profile}[/cyan]")
    console.print(f"  Rate:     [cyan]{rate_limit} req/s[/cyan]")
    console.print(f"  Sessions: [cyan]{len(sessions)}[/cyan]")
    console.print(f"  Reports:  [cyan]{', '.join(report_formats_raw)}[/cyan]")

    confirm = questionary.confirm("\nStart scan?", default=True, style=_Q_STYLE).ask()
    if not confirm:
        console.print("[dim]Cancelled.[/dim]")
        sys.exit(0)

    config = ScanConfig(
        target=target,
        allowed_scope=allowed_scope,
        technology_hint=technology,
        scan_profile=profile,
        sessions=sessions,
        rate_limit=rate_limit,
    )
    asyncio.run(_run_scan(config, report_formats_raw, output_dir))


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--target",       "-t", default=None,   help="Target URL")
@click.option("--technology",   "-T", default=None,   help="Technology hint (wordpress/laravel/django/express/nextjs/generic/auto)")
@click.option("--profile",      "-p", default="full", help="Scan profile (recon/endpoint/access_control/disclosure/configuration/full)")
@click.option("--scope",        "-s", default="",     help="Allowed scope (comma-separated domains)")
@click.option("--auth-session", "-a", default=None,   multiple=True, help="Session cookie string (use multiple times for multiple sessions)")
@click.option("--rate-limit",   "-r", default=5.0,    help="Max requests per second", type=float)
@click.option("--timeout",      "-x", default=15.0,   help="Request timeout in seconds", type=float)
@click.option("--depth",        "-d", default=3,      help="Crawl depth", type=int)
@click.option("--report",       "-R", default=["terminal", "json", "html"], multiple=True, help="Report format(s): terminal/json/html")
@click.option("--output",       "-o", default="./scopehunter_reports", help="Output directory")
@click.option("--no-verify-ssl",      is_flag=True,   help="Disable SSL verification")
@click.option("--proxy",              default=None,   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
@click.option("--verbose",     "-v",  is_flag=True,   help="Enable debug logging")
@click.option("--interactive", "-i",  is_flag=True,   help="Force interactive mode")
@click.version_option(__version__, "-V", "--version")
def main(
    target: Optional[str],
    technology: Optional[str],
    profile: str,
    scope: str,
    auth_session: tuple,
    rate_limit: float,
    timeout: float,
    depth: int,
    report: tuple,
    output: str,
    no_verify_ssl: bool,
    proxy: Optional[str],
    verbose: bool,
    interactive: bool,
) -> None:
    """
    \b
    ScopeHunter — Technology-Aware Security Assessment Assistant
    For authorized web application security testing only.
    \b
    Examples:
      scopehunter                                          # Interactive mode
      scopehunter -t https://example.com                  # Auto-detect
      scopehunter -T wordpress -t https://example.com
      scopehunter -t https://example.com -p access_control -R html
    """
    _configure_logging(verbose)

    # If no target or interactive flag → launch interactive mode
    if not target or interactive:
        _run_interactive()
        return

    # Build session profiles from --auth-session flags
    sessions: list[SessionProfile] = []
    for i, raw_cookie in enumerate(auth_session):
        profile_name = f"session_{i + 1}"
        cookies: dict[str, str] = {}
        for part in raw_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        sessions.append(SessionProfile(name=profile_name, cookies=cookies))

    # Parse scope
    allowed_scope = [s.strip() for s in scope.split(",") if s.strip()]

    # Normalize technology hint
    tech_hint: Optional[str] = None
    if technology and technology.lower() not in ("auto", ""):
        tech_map = {
            "wordpress": "WordPress", "wp": "WordPress",
            "laravel": "Laravel",
            "django": "Django",
            "express": "Express.js", "expressjs": "Express.js",
            "nextjs": "Next.js", "next": "Next.js",
            "generic": "generic",
        }
        tech_hint = tech_map.get(technology.lower(), technology)

    config = ScanConfig(
        target=target,
        allowed_scope=allowed_scope,
        technology_hint=tech_hint,
        scan_profile=profile,
        sessions=sessions,
        rate_limit=rate_limit,
        timeout=timeout,
        max_depth=depth,
        verify_ssl=not no_verify_ssl,
        proxy=proxy,
    )

    asyncio.run(_run_scan(config, list(report), Path(output)))


if __name__ == "__main__":
    main()
