#!/usr/bin/env python3
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

# Internal modules
from validators import identify_ioc_type
from database import Database
from providers.virustotal import VirusTotalProvider
from providers.hybridanalysis import HybridAnalysisProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.alienvault import AlienVaultProvider
from providers.greynoise import GreyNoiseProvider
from providers.google_safebrowsing import GoogleSafeBrowsingProvider 

# Environment settings
BASE_DIR = "/home/felipe/ioc-search"
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = typer.Typer(help="IOC Analyzer with Network Intelligence")
console = Console()
db = Database()

def get_color(verdict):
    """Returns a color based on the severity of the verdict."""
    if isinstance(verdict, int): return "red" if verdict > 0 else "green"
    v = str(verdict).lower()
    malicious_terms = ["malicious", "suspicious", "phishing", "malware", "social_engineering"]
    clean_terms = ["clean", "harmless", "safe", "benign", "0", "none"]
    if v in malicious_terms: return "red"
    if v in clean_terms: return "green"
    return "yellow"

def display_results(results, ioc):
    """Displays detailed report with ASN/ISP info and provider details."""
    
    # 1. Network Information Extraction (ASN/ISP)
    network_info = None
    for res in results:
        if res.get("status") == "success":
            # Attempt to capture network data from providers like AbuseIPDB or VirusTotal
            isp = res.get("isp") or res.get("as_owner")
            asn = res.get("asn")
            if isp or asn:
                network_info = f"[bold white]Provider/Org:[/bold white] {isp or 'N/A'} | [bold white]ASN:[/bold white] {asn or 'N/A'}"
                break

    if network_info:
        console.print(Panel(network_info, title="🌐 Network Information", border_style="blue"))

    # 2. Results Table Construction
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
            
            # Specific details based on each API return
            detail = "Data retrieved successfully"
            if p_name == "VirusTotal":
                detail = f"{verdict} detections in AV engines"
            elif p_name == "AbuseIPDB":
                conf = res.get('confidence', 'N/A')
                detail = f"Confidence Score: {conf}%"
            elif p_name == "HybridAnalysis":
                detail = f"Threat Score: {res.get('score', 'N/A')}/100"
            elif p_name == "GreyNoise":
                detail = f"Classification: {str(verdict).capitalize()}"
            elif p_name == "SafeBrowsing":
                detail = f"Google Status: {str(verdict).replace('_', ' ')}"
            elif p_name == "AlienVault":
                detail = f"Found in {res.get('pulse_count', 0)} OTX Pulses"

            table.add_row(p_name, f"[{color}]{str(verdict).upper()}[/{color}]", detail)
            
        elif status == "skipped":
            table.add_row(p_name, "[white]SKIP[/white]", "Incompatible type")
        else:
            table.add_row(p_name, "[red]ERROR[/red]", f"Failed: {res.get('error', 'Timeout/API')}")
            
    console.print(table)

def analyze_single_ioc(ioc: str, is_last: bool = False):
    """Handles the analysis of an individual IOC."""
    ioc = ioc.strip()
    if not ioc: return
    
    ioc_type = identify_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print(f"[red]![/red] Unidentified type: {ioc}")
        return

    # 48-hour cache (validated in database.py)
    cached = db.get_cached_result(ioc)
    if cached:
        console.print(f"[bold yellow][CACHE Active][/bold yellow] Displaying saved data for {ioc}:")
        display_results(json.loads(cached), ioc)
        return

    console.print(f"[*] Searching {ioc_type.upper()}: [bold cyan]{ioc}[/bold cyan]...")

    providers = [
        VirusTotalProvider(os.getenv("VT_API_KEY")),
        HybridAnalysisProvider(os.getenv("HYBRID_API_KEY")),
        AbuseIPDBProvider(os.getenv("ABUSE_API_KEY")),
        AlienVaultProvider(os.getenv("OTX_API_KEY")),
        GreyNoiseProvider(os.getenv("GREYNOISE_API_KEY")),
        GoogleSafeBrowsingProvider(os.getenv("GOOGLE_API_KEY"))
    ]

    results = []
    for p in providers:
        try:
            res = p.fetch(ioc, ioc_type)
            results.append(res)
        except Exception as e:
            results.append({"provider": p.name, "status": "error", "error": str(e)})

    db.save_result(ioc, ioc_type, results)
    display_results(results, ioc)

    # Pause between requests to avoid rate limiting
    if not is_last:
        console.print(f"[dim]🕒 7s pause to respect API limits...[/dim]")
        time.sleep(7)

@app.command()
def scan(ioc: str = typer.Option(None, "-i"), file: str = typer.Option(None, "-f")):
    """Analyzes one or multiple IOCs with automatic old cache cleanup."""
    db.cleanup_old_records()
    if ioc:
        analyze_single_ioc(ioc, is_last=True)
    elif file and os.path.exists(file):
        with open(file, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
            for i, line in enumerate(lines):
                analyze_single_ioc(line, is_last=(i == len(lines)-1))
    else:
        console.print("[bold red]Error:[/bold red] Use -i <ioc> or -f <file>.")

@app.command()
def history():
    """Shows query history from the last 48 hours."""
    db.cleanup_old_records()
    records = db.get_all_history()
    if not records:
        console.print("[yellow]No recent analysis available in history (48h).[/yellow]")
        return

    table = Table(title="📜 Recent Query Records")
    table.add_column("Date/Time", style="cyan")
    table.add_column("IOC", style="white")
    table.add_column("Threat Status", justify="center")

    for dt, ioc_type, ioc, data_raw in records:
        try:
            data = json.loads(data_raw)
            alerts = sum(1 for r in data if r.get('status') == 'success' and get_color(r.get('verdict', 0)) == "red")
            status = f"[bold red]⚠ {alerts} ALERT(S)[/bold red]" if alerts > 0 else "[bold green]✓ CLEAN[/bold green]"
            table.add_row(dt, ioc, status)
        except:
            table.add_row(dt, ioc, "[dim]Corrupted data[/dim]")
            
    console.print(table)

if __name__ == "__main__":
    app()