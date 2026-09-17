#!/usr/bin/env python3
import csv
from datetime import datetime
import json
import os
import time

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from database import Database
from providers.abuseipdb import AbuseIPDBProvider
from providers.alienvault import AlienVaultProvider
from providers.google_safebrowsing import GoogleSafeBrowsingProvider
from providers.greynoise import GreyNoiseProvider
from providers.hybridanalysis import HybridAnalysisProvider
from providers.virustotal import VirusTotalProvider
from validators import identify_ioc_type

# Environment settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = typer.Typer(help="IOC Analyzer with Network Intelligence")
console = Console()
db = Database(os.path.join(BASE_DIR, "ioc_cache.db"))


def get_color(verdict):
    """Returns a color based on the severity of the verdict."""
    if isinstance(verdict, int):
        return "red" if verdict > 0 else "green"
    v = str(verdict).lower()
    malicious_terms = [
        "malicious",
        "suspicious",
        "phishing",
        "malware",
        "social_engineering",
    ]
    clean_terms = ["clean", "harmless", "safe", "benign", "0", "none"]
    if v in malicious_terms:
        return "red"
    if v in clean_terms:
        return "green"
    return "yellow"


def display_results(results, ioc):
    """Displays detailed report and returns results for export."""
    network_info = None
    for res in results:
        if res.get("status") == "success":
            isp = res.get("isp") or res.get("as_owner")
            asn = res.get("asn")
            if isp or asn:
                network_info = f"[bold white]Provider/Org:[/bold white] {isp or 'N/A'} | [bold white]ASN:[/bold white] {asn or 'N/A'}"
                break

    if network_info:
        console.print(
            Panel(
                network_info,
                title="Network Information",
                border_style="blue",
            )
        )

    table = Table(title=f"Results for: [bold cyan]{ioc}[/bold cyan]")
    table.add_column("Search Engine", style="magenta")
    table.add_column("Verdict", justify="center")
    table.add_column("Technical Details", style="blue")

    for res in results:
        p_name = res.get("provider", "Unknown")
        status = res.get("status", "N/A")

        if status == "success":
            verdict = res.get("verdict", res.get("malicious", "INFO"))
            color = get_color(verdict)
            detail = res.get("details", "Data retrieved successfully")

            if p_name == "VirusTotal" and "details" not in res:
                detail = f"{verdict} detections in AV engines"
            elif p_name == "AbuseIPDB" and "details" not in res:
                detail = f"Confidence Score: {res.get('confidence', 'N/A')}%"
            elif p_name == "AlienVault" and "details" not in res:
                detail = f"Found in {res.get('pulse_count', 0)} OTX Pulses"
            elif p_name == "HybridAnalysis" and "details" not in res:
                detail = res.get(
                    "note", f"Threat score: {res.get('threat_score', 'N/A')}"
                )

            table.add_row(
                p_name, f"[{color}]{str(verdict).upper()}[/{color}]", detail
            )
        elif status in ["skipped", "skip"]:
            table.add_row(
                p_name,
                "[white]SKIP[/white]",
                res.get("details", "Incompatible type"),
            )
        elif status == "not_found":
            table.add_row(
                p_name,
                "[yellow]NOT FOUND[/yellow]",
                res.get("details", "Not found in database"),
            )
        else:
            table.add_row(
                p_name,
                "[red]ERROR[/red]",
                f"Failed: {res.get('error', res.get('details', 'API Error'))}",
            )

    console.print(table)
    return results


def analyze_single_ioc(ioc: str, is_last: bool = False):
    """Handles analysis and returns data for export."""
    ioc = ioc.strip()
    if not ioc or ioc.startswith("#"):
        return None

    ioc_type = identify_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print(f"[red]![/red] Unidentified type: {ioc}")
        return None

    cached = db.get_cached_result(ioc)
    if cached:
        console.print(
            f"[bold yellow][CACHE Active][/bold yellow] Saved data for {ioc}:"
        )
        return display_results(json.loads(cached), ioc)

    console.print(
        f"[*] Searching {ioc_type.upper()}: [bold cyan]{ioc}[/bold cyan]..."
    )

    providers = [
        VirusTotalProvider(os.getenv("VT_API_KEY")),
        HybridAnalysisProvider(os.getenv("HYBRID_API_KEY")),
        AbuseIPDBProvider(os.getenv("ABUSE_API_KEY")),
        AlienVaultProvider(os.getenv("OTX_API_KEY")),
        GreyNoiseProvider(os.getenv("GREYNOISE_API_KEY")),
        GoogleSafeBrowsingProvider(os.getenv("GOOGLE_API_KEY")),
    ]

    results = []
    for p in providers:
        try:
            res = p.fetch(ioc, ioc_type)
            results.append(res)
        except Exception as e:
            results.append(
                {"provider": p.name, "status": "error", "error": str(e)}
            )

    db.save_result(ioc, ioc_type, results)
    data = display_results(results, ioc)

    if not is_last:
        console.print("[dim]7s pause for API limits...[/dim]")
        time.sleep(7)

    return data


def run_scan_workflow(ioc: str = None, file: str = None, export: str = None):
    """Core logic to handle scanning and exporting."""
    db.cleanup_old_records()
    final_data = {}

    if not ioc and not file:
        console.print(
            "[red]Error:[/red] Please provide an indicator with [bold]-i[/bold] or a file with [bold]-f[/bold]."
        )
        raise typer.Exit(code=1)

    if ioc:
        res = analyze_single_ioc(ioc, is_last=True)
        if res:
            final_data[ioc] = res
    elif file:
        if not os.path.exists(file):
            console.print(f"[red]Error:[/red] File '{file}' not found.")
            raise typer.Exit(code=1)

        with open(file, "r") as f:
            lines = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]

        for i, line in enumerate(lines):
            res = analyze_single_ioc(line, is_last=(i == len(lines) - 1))
            if res:
                final_data[line] = res

    if export and final_data:
        export_fmt = export.lower().strip().lstrip(".")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if export_fmt == "json":
            filename = f"result_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(final_data, f, indent=4)
            console.print(
                f"\n[bold green]Results exported to JSON: {filename}[/bold green]"
            )

        elif export_fmt == "csv":
            filename = f"result_{timestamp}.csv"
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["IOC", "Provider", "Status", "Verdict", "Details"]
                )
                for ioc_key, providers in final_data.items():
                    for p in providers:
                        verdict = p.get("verdict", p.get("malicious", "N/A"))
                        details = p.get("details", p.get("error", "N/A"))
                        writer.writerow(
                            [
                                ioc_key,
                                p.get("provider"),
                                p.get("status"),
                                verdict,
                                details,
                            ]
                        )
            console.print(
                f"\n[bold green]Results exported to CSV: {filename}[/bold green]"
            )
        else:
            console.print(
                f"\n[bold red]Invalid export format: '{export}'. Use 'json' or 'csv'.[/bold red]"
            )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    ioc: str = typer.Option(None, "-i", "--indicator", help="Single IOC"),
    file: str = typer.Option(None, "-f", "--file", help="File with IOCs"),
    export: str = typer.Option(
        None, "-e", "--export", help="Export format: 'json' or 'csv'"
    ),
):
    """IOC Analyzer CLI - Root Command."""
    if ctx.invoked_subcommand is None:
        if ioc or file:
            run_scan_workflow(ioc=ioc, file=file, export=export)
        else:
            console.print(
                "[yellow]Usage: ioc-search -f <file> or ioc-search scan -i <indicator>[/yellow]"
            )
            console.print("Run [bold]ioc-search --help[/bold] for options.")


@app.command()
def scan(
    ioc: str = typer.Option(None, "-i", "--indicator", help="Single IOC"),
    file: str = typer.Option(None, "-f", "--file", help="File with IOCs"),
    export: str = typer.Option(
        None, "-e", "--export", help="Export format: 'json' or 'csv'"
    ),
):
    """Scan IOCs and optionally export results with automatic naming."""
    run_scan_workflow(ioc=ioc, file=file, export=export)


@app.command()
def history():
    """Shows query history."""
    db.cleanup_old_records()
    records = db.get_all_history()
    if not records:
        console.print("[yellow]No recent history.[/yellow]")
        return

    table = Table(title="Recent Query Records")
    table.add_column("Date/Time", style="cyan")
    table.add_column("IOC", style="white")
    table.add_column("Threat Status", justify="center")

    for dt, ioc_type, ioc, data_raw in records:
        try:
            data = json.loads(data_raw)
            alerts = sum(
                1
                for r in data
                if r.get("status") == "success"
                and get_color(r.get("verdict", 0)) == "red"
            )
            status = (
                f"[bold red]{alerts} ALERT(S)[/bold red]"
                if alerts > 0
                else "[bold green]CLEAN[/bold green]"
            )
            table.add_row(dt, ioc, status)
        except Exception:
            table.add_row(dt, ioc, "[dim]Corrupted[/dim]")
    console.print(table)


if __name__ == "__main__":
    app()