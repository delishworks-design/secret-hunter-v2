import click
import json
import yaml
from rich.console import Console
from dashboard import show_welcome, show_summary, show_findings_table, show_error, show_success, show_banner, create_progress
from report import ReportGenerator

console = Console()


@click.group()
@click.version_option(version="2.0.0", prog_name="secret-hunter-v2")
def cli():
    """Secret Hunter V2 - Security Auditing Tool"""
    show_welcome()


@cli.command()
@click.option("--mode", type=click.Choice(["local", "github", "website", "git", "multi"]), required=True, help="Scan mode")
@click.option("--target", required=True, help="Target to scan (path, repo name, or URL)")
@click.option("--output", type=click.Choice(["json", "sarif", "html", "csv"]), default="json", help="Output format")
@click.option("--severity", default="LOW", help="Minimum severity level")
@click.option("--threads", default=10, help="Number of threads")
@click.option("--depth", default=3, help="Scan depth")
@click.option("--history-depth", default=100, help="History depth for git/github scans")
@click.option("--output-dir", default=None, help="Output directory for reports")
@click.option("--extensions", default=None, help="Comma-separated file extensions to scan")
@click.option("--exclude", default=None, help="Comma-separated directories to exclude")
def scan(mode, target, output, severity, threads, depth, history_depth, output_dir, extensions, exclude):
    """Scan targets for secrets and credentials."""
    from local_scanner import LocalScanner
    from github_scanner import GitHubScanner
    from website_scanner import WebsiteScanner
    from git_scanner import GitScanner
    from multi_scanner import MultiScanner

    ext_list = extensions.split(",") if extensions else None
    exclude_list = exclude.split(",") if exclude else None

    results = {}
    with create_progress() as progress:
        task = progress.add_task(f"Scanning {target} ({mode} mode)...", total=None)

        if mode == "local":
            scanner = LocalScanner()
            results = scanner.scan_directory(target, extensions=ext_list, exclude=exclude_list)
        elif mode == "github":
            scanner = GitHubScanner()
            results = scanner.scan_repo(target, scan_history=True, history_depth=history_depth)
        elif mode == "website":
            scanner = WebsiteScanner()
            results = scanner.scan_url(target, depth=depth)
        elif mode == "git":
            if target.startswith(("http://", "https://", "git@")):
                scanner = GitScanner()
                results = scanner.scan_remote_repo(target, depth=history_depth)
            else:
                scanner = GitScanner()
                results = scanner.scan_local_repo(target, depth=history_depth)
        elif mode == "multi":
            scanner = MultiScanner(threads=threads)
            try:
                results = scanner.scan_from_config(target)
            except Exception:
                targets = [{"type": "local", "target": target}]
                results = scanner.scan_multiple(targets)

        progress.update(task, completed=True)

    if "error" in results:
        show_error(results["error"])
        return

    findings = results.get("findings", [])

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_severity = severity_order.get(severity.upper(), 0)
    filtered_findings = [
        f for f in findings
        if severity_order.get(f.get("severity", "INFO").upper(), 0) >= min_severity
    ]
    results["findings"] = filtered_findings

    show_summary(results)
    show_findings_table(filtered_findings)

    if output_dir or output:
        generator = ReportGenerator(output_dir)
        if output == "json":
            filepath = generator.export_json(results)
        elif output == "sarif":
            filepath = generator.export_sarif(results)
        elif output == "html":
            filepath = generator.export_html(results)
        elif output == "csv":
            filepath = generator.export_csv(results)
        show_success(f"Report saved: {filepath}")


@cli.command()
@click.option("--type", "brute_type", type=click.Choice(["login", "directories", "api_key"]), required=True, help="Brute force type")
@click.option("--target", required=True, help="Target URL")
@click.option("--wordlist", required=True, help="Path to wordlist file")
@click.option("--threads", default=10, help="Number of threads")
@click.option("--rate-limit", default=10, help="Requests per second")
@click.option("--proxy", default=None, help="Proxy URL")
def bruteforce(brute_type, target, wordlist, threads, rate_limit, proxy):
    """Brute force login pages, directories, or API keys."""
    from bruteforcer import BruteForcer

    try:
        with open(wordlist, "r") as f:
            wordlist_items = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        show_error(f"Wordlist not found: {wordlist}")
        return

    scanner = BruteForcer(threads=threads, rate_limit=rate_limit, proxy=proxy)

    results = {}
    with create_progress() as progress:
        task = progress.add_task(f"Brute forcing {target}...", total=None)

        if brute_type == "login":
            usernames = wordlist_items
            passwords = wordlist_items[:50]
            results = scanner.brute_force_login(target, usernames, passwords)
        elif brute_type == "directories":
            results = scanner.brute_force_directories(target, wordlist_items)
        elif brute_type == "api_key":
            results = scanner.brute_force_api_key(target, wordlist_items)

        progress.update(task, completed=True)

    show_summary(results)

    if results.get("results"):
        table_results = []
        for r in results["results"]:
            table_results.append({
                "file": r.get("url", r.get("directory", "")),
                "line": 0,
                "pattern": r.get("type", "found"),
                "severity": "HIGH",
                "description": f"Status: {r.get('status_code', 'N/A')}",
                "match": r.get("username", r.get("key", r.get("directory", ""))),
            })
        show_findings_table(table_results)

    show_success(f"Completed: {results.get('successful', results.get('found', 0))} results found")


@cli.command()
@click.option("--type", "stuff_type", type=click.Choice(["login"]), required=True, help="Stuffing type")
@click.option("--target", required=True, help="Target URL")
@click.option("--credentials", required=True, help="Path to credentials file (JSON)")
@click.option("--threads", default=10, help="Number of threads")
@click.option("--rate-limit", default=10, help="Requests per second")
@click.option("--proxy", default=None, help="Proxy URL")
def stuff(stuff_type, target, credentials, threads, rate_limit, proxy):
    """Credential stuffing against login endpoints."""
    from credential_stuffer import CredentialStuffer

    try:
        with open(credentials, "r") as f:
            if credentials.endswith((".yml", ".yaml")):
                cred_data = yaml.safe_load(f)
            else:
                cred_data = json.load(f)

        if isinstance(cred_data, list):
            cred_list = cred_data
        elif isinstance(cred_data, dict) and "credentials" in cred_data:
            cred_list = cred_data["credentials"]
        else:
            cred_list = [cred_data]
    except Exception as e:
        show_error(f"Failed to load credentials: {e}")
        return

    scanner = CredentialStuffer(threads=threads, rate_limit=rate_limit, proxy=proxy)

    results = {}
    with create_progress() as progress:
        task = progress.add_task(f"Credential stuffing {target}...", total=None)
        results = scanner.credential_stuff_login(target, cred_list)
        progress.update(task, completed=True)

    show_summary(results)

    if results.get("results"):
        table_results = []
        for r in results["results"]:
            table_results.append({
                "file": r.get("url", ""),
                "line": 0,
                "pattern": r.get("type", "credential_test"),
                "severity": "CRITICAL" if r.get("success") else "INFO",
                "description": f"User: {r.get('username', '')}",
                "match": r.get("password", ""),
            })
        show_findings_table(table_results)

    show_success(f"Completed: {results.get('successful', 0)} successful credentials found")


@cli.command()
@click.option("--type", "bypass_type", type=click.Choice(["header", "jwt", "path", "method"]), required=True, help="Bypass type")
@click.option("--target", required=True, help="Target URL")
@click.option("--token", default=None, help="JWT token for jwt bypass")
@click.option("--proxy", default=None, help="Proxy URL")
def bypass(bypass_type, target, token, proxy):
    """Test authentication bypass vulnerabilities."""
    from auth_bypass import AuthBypass

    scanner = AuthBypass(proxy=proxy)

    results = {}
    with create_progress() as progress:
        task = progress.add_task(f"Testing auth bypass on {target}...", total=None)

        if bypass_type == "header":
            results = scanner.bypass_header_manipulation(target)
        elif bypass_type == "jwt":
            if not token:
                show_error("JWT token is required for jwt bypass")
                return
            results = scanner.bypass_jwt_none(target, token)
        elif bypass_type == "path":
            results = scanner.bypass_path_traversal(target)
        elif bypass_type == "method":
            results = scanner.bypass_method_override(target)

        progress.update(task, completed=True)

    show_summary(results)

    if results.get("results"):
        table_results = []
        for r in results["results"]:
            table_results.append({
                "file": r.get("url", ""),
                "line": 0,
                "pattern": r.get("type", "bypass_test"),
                "severity": "CRITICAL" if r.get("changed") or r.get("bypassed") else "INFO",
                "description": r.get("header", r.get("description", r.get("method", ""))),
                "match": r.get("value", r.get("payload", "")),
            })
        show_findings_table(table_results)

    show_success(f"Completed: {results.get('successful', 0)} potential bypasses found")


@cli.command()
@click.option("--type", "acquire_type", type=click.Choice(["debug", "env", "config", "backup"]), required=True, help="Acquisition type")
@click.option("--target", required=True, help="Target URL")
@click.option("--proxy", default=None, help="Proxy URL")
def acquire(acquire_type, target, proxy):
    """Acquire secrets from debug endpoints, env files, config files, or backups."""
    from secret_acquirer import SecretAcquirer

    scanner = SecretAcquirer(proxy=proxy)

    results = {}
    with create_progress() as progress:
        task = progress.add_task(f"Acquiring secrets from {target}...", total=None)

        if acquire_type == "debug":
            results = scanner.acquire_from_debug(target)
        elif acquire_type == "env":
            results = scanner.acquire_from_env(target)
        elif acquire_type == "config":
            results = scanner.acquire_from_config(target)
        elif acquire_type == "backup":
            results = scanner.acquire_from_backup(target)

        progress.update(task, completed=True)

    show_summary(results)

    if results.get("results"):
        table_results = []
        for r in results["results"]:
            table_results.append({
                "file": r.get("url", ""),
                "line": 0,
                "pattern": r.get("pattern", "unknown"),
                "severity": r.get("severity", "HIGH"),
                "description": r.get("description", ""),
                "match": r.get("match", "")[:100],
            })
        show_findings_table(table_results)

    show_success(f"Completed: {results.get('secrets_found', 0)} secrets found")


@cli.command()
@click.option("--results", "results_file", required=True, help="Path to results JSON file")
@click.option("--format", "export_format", type=click.Choice(["json", "sarif", "html", "csv"]), required=True, help="Export format")
@click.option("--output-dir", default=None, help="Output directory")
@click.option("--filename", default=None, help="Output filename")
def report(results_file, export_format, output_dir, filename):
    """Export scan results to various formats."""
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
    except FileNotFoundError:
        show_error(f"Results file not found: {results_file}")
        return
    except json.JSONDecodeError:
        show_error(f"Invalid JSON in results file: {results_file}")
        return

    generator = ReportGenerator(output_dir)

    if export_format == "json":
        filepath = generator.export_json(results, filename)
    elif export_format == "sarif":
        filepath = generator.export_sarif(results, filename)
    elif export_format == "html":
        filepath = generator.export_html(results, filename)
    elif export_format == "csv":
        filepath = generator.export_csv(results, filename)

    show_success(f"Report exported: {filepath}")


@cli.command()
def version():
    """Show version information."""
    show_banner()
    console.print("[bold]Secret Hunter V2[/bold] - Security Auditing Tool")
    console.print("Version: [cyan]2.0.0[/cyan]")
    console.print("Author: Schatz")
    console.print()


if __name__ == "__main__":
    cli()
