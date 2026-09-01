from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich import box
from datetime import datetime

console = Console()

BANNER = """
╔═══════════════════════════════════════════════╗
║       SECRET HUNTER V2 - Schatz               ║
║       Security Auditing Tool v2.0.0           ║
╚═══════════════════════════════════════════════╝
"""


def show_welcome():
    console.print()
    console.print(Panel(BANNER, style="bold cyan", border_style="cyan"))
    console.print()
    console.print("[bold white]Secret Hunter V2[/bold white] - Advanced Security Auditing Tool", style="cyan")
    console.print("[dim]Scan local files, GitHub repos, websites, and git repositories for secrets and credentials[/dim]")
    console.print()
    console.print("[bold]Available Commands:[/bold]")
    console.print("  [cyan]scan[/cyan]        - Scan targets for secrets")
    console.print("  [cyan]bruteforce[/cyan]  - Brute force login/directories/APIs")
    console.print("  [cyan]stuff[/cyan]       - Credential stuffing")
    console.print("  [cyan]bypass[/cyan]      - Authentication bypass testing")
    console.print("  [cyan]acquire[/cyan]     - Acquire secrets from endpoints")
    console.print("  [cyan]report[/cyan]      - Generate reports")
    console.print()
    console.print("[dim]Use --help on any command for more information[/dim]")
    console.print()


def show_summary(results: dict):
    findings = results.get("findings", [])
    stats = results.get("stats", {})
    scan_type = results.get("scan_type", "unknown")
    target = results.get("target", "unknown")

    summary_table = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Scan Type", scan_type)
    summary_table.add_row("Target", target)
    summary_table.add_row("Total Findings", str(len(findings)))
    summary_table.add_row("Files Scanned", str(stats.get("files_scanned", stats.get("total_files_scanned", 0))))
    summary_table.add_row("Lines Scanned", str(stats.get("lines_scanned", 0)))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    if any(severity_counts.values()):
        console.print()
        sev_table = Table(title="Severity Distribution", box=box.ROUNDED, border_style="yellow")
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        sev_table.add_column("Bar", min_width=20)

        max_count = max(severity_counts.values()) if severity_counts.values() else 1
        severity_styles = {
            "CRITICAL": "bold red",
            "HIGH": "bold magenta",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "dim",
        }

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts[sev]
            if count > 0:
                bar_width = int((count / max_count) * 20)
                bar = "█" * bar_width + "░" * (20 - bar_width)
                sev_table.add_row(
                    f"[{severity_styles[sev]}]{sev}[/{severity_styles[sev]}]",
                    str(count),
                    f"[{severity_styles[sev]}]{bar}[/{severity_styles[sev]}]",
                )

        console.print(sev_table)

    console.print(summary_table)


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


def show_findings_table(findings: list):
    if not findings:
        console.print("[yellow]No findings to display[/yellow]")
        return

    table = Table(title="Findings", box=box.ROUNDED, border_style="red")
    table.add_column("#", style="dim", width=5)
    table.add_column("Severity", width=10)
    table.add_column("Pattern", width=25)
    table.add_column("Location", width=40)
    table.add_column("Match", max_width=30)

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold magenta",
        "MEDIUM": "bold yellow",
        "LOW": "bold blue",
        "INFO": "dim",
    }

    for i, finding in enumerate(findings[:100], 1):
        severity = finding.get("severity", "INFO")
        style = severity_styles.get(severity, "white")

        file_path = finding.get("file", "unknown")
        line = finding.get("line", "-")
        location = f"{file_path}:{line}" if line != "-" else file_path

        if len(location) > 40:
            location = "..." + location[-37:]

        match_text = finding.get("match", "")[:30]

        table.add_row(
            str(i),
            f"[{style}]{severity}[/{style}]",
            finding.get("pattern", "Unknown"),
            location,
            match_text,
        )

    console.print(table)

    if len(findings) > 100:
        console.print(f"[dim]... and {len(findings) - 100} more findings[/dim]")


def show_scan_progress(description: str = "Scanning..."):
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


def show_error(message: str):
    console.print(f"[bold red]Error:[/bold red] {message}")


def show_success(message: str):
    console.print(f"[bold green]Success:[/bold green] {message}")


def show_warning(message: str):
    console.print(f"[bold yellow]Warning:[/bold yellow] {message}")


def show_info(message: str):
    console.print(f"[bold cyan]Info:[/bold cyan] {message}")


def show_report_export(filepath: str, format_type: str):
    console.print(f"[bold green]Report exported:[/bold green] {filepath} ({format_type})")


def show_banner():
    console.print(BANNER, style="bold cyan")
