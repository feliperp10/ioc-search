import typer
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from concurrent.futures import ThreadPoolExecutor, as_completed

# Importacao dos provedores
from config import settings
from validators import identify_ioc_type
from providers.virustotal import VirusTotalProvider
from providers.alienvault import AlienVaultProvider
from providers.hybridanalysis import HybridAnalysisProvider
from providers.google_safebrowsing import GoogleSafeBrowsingProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.greynoise import GreyNoiseProvider

app = typer.Typer(add_completion=False)
console = Console()

def run_provider(provider, ioc, ioc_type):
    try:
        return provider.fetch(ioc, ioc_type)
    except Exception as e:
        nome = provider.__class__.__name__.replace("Provider", "")
        return {"provider": nome, "error": str(e)}

def analyze_single_ioc(ioc: str, providers: list):
    ioc = ioc.strip()
    ioc_type = identify_ioc_type(ioc)
    
    if ioc_type == "unknown":
        console.print(f"ERRO: IOC invalido: '{ioc}'")
        return None

    console.print(f"\n[*] Analisando {ioc_type.upper()}: [bold cyan]{ioc}[/bold cyan]")

    table = Table(show_header=True, header_style="bold white on blue", expand=True, box=box.ROUNDED)
    table.add_column("Provider", width=18)
    table.add_column("Status / Resultado", justify="center", width=22)
    table.add_column("Detalhes e Contexto")

    ioc_results = {"ioc": ioc, "type": ioc_type, "data": []}

    with console.status("[bold green]Consultando APIs...[/bold green]"):
        with ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = {executor.submit(run_provider, p, ioc, ioc_type): p for p in providers}
            
            for future in as_completed(futures):
                res = future.result()
                if not res or res.get("status") == "skipped":
                    continue
                
                nome = res.get("provider", "Desconhecido")
                ioc_results["data"].append(res)
                
                if "error" in res:
                    msg = "NF / SEM DADOS" if "404" in res['error'] else "FALHA TECNICA"
                    table.add_row(nome, f"[white]{msg}[/white]", f"[dim]{res['error']}[/dim]")
                
                elif res.get("status") == "not_found":
                    table.add_row(nome, "[bold bright_green]LIMPO / NF[/bold bright_green]", "Nenhum registro encontrado.")
                
                else:
                    # --- VIRUSTOTAL ---
                    if nome == "VirusTotal":
                        mal = res.get('malicious', 0)
                        cor = "bright_red" if mal > 3 else "yellow" if mal > 0 else "bright_green"
                        asn_info = f" | ASN: {res.get('asn')} ({res.get('as_owner')})" if res.get('asn') != "N/A" else ""
                        detalhes = f"Rep: {res.get('reputation')}{asn_info}"
                        table.add_row(nome, Text(f"{mal} Detecoes", style=f"bold {cor}"), detalhes)

                    # --- ABUSEIPDB ---
                    elif nome == "AbuseIPDB":
                        score = res.get('score', 0)
                        cor = "bright_red" if score > 50 else "yellow" if score > 0 else "white"
                        detalhes = f"ISP: {res.get('isp')} | Pais: {res.get('country')} | Uso: {res.get('usage_type')}"
                        table.add_row(nome, Text(f"Confianca: {score}%", style=f"bold {cor}"), detalhes)

                    # --- HYBRID ANALYSIS ---
                    elif nome == "HybridAnalysis":
                        v = res.get('verdict', 'unknown').upper()
                        score = res.get('score', 0)
                        cor = "bright_red" if v == "MALICIOUS" else "yellow" if v == "SUSPICIOUS" else "bright_green"
                        table.add_row(nome, Text(v, style=f"bold {cor}"), f"Threat Score: {score}/100")

                    # --- GOOGLE SAFE BROWSING ---
                    elif nome == "GoogleSafeBrowsing":
                        v = res.get('verdict', '').upper()
                        if v == "MALICIOUS":
                            status = Text("MALICIOSO", style="bold bright_red")
                            detalhes = f"Tipo: {res.get('threat_type')}"
                        else:
                            status = Text("LIMPO", style="bold bright_green")
                            detalhes = "URL segura segundo o Google"
                        table.add_row(nome, status, detalhes)

                    # --- ALIENVAULT ---
                    elif nome == "AlienVault":
                        cnt = res.get('pulses_count', 0)
                        cor = "bright_red" if cnt > 0 else "bright_green"
                        table.add_row(nome, Text(f"{cnt} Pulses", style=f"bold {cor}"), res.get('details'))

                    # --- GREYNOISE ---
                    elif nome == "GreyNoise":
                        classif = res.get('classification', 'unknown')
                        is_riot = res.get('riot', False)
                        cor = "bright_green" if classif == "benign" or is_riot else "bright_red" if classif == "malicious" else "white"
                        table.add_row(nome, Text(classif.upper(), style=f"bold {cor}"), f"Tag: {res.get('name')}")

                    else:
                        table.add_row(nome, "[white]Concluido[/white]", "Dados processados.")
                
                table.add_section()

    console.print(table)
    return ioc_results

def export_data(results, format_ext):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{timestamp}.{format_ext}"
    if format_ext == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
    elif format_ext == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IOC", "Tipo", "Provider", "Status", "Info_Adicional"])
            for r in results:
                for d in r["data"]:
                    extra = d.get("as_owner") or d.get("isp") or d.get("verdict") or "N/A"
                    writer.writerow([r["ioc"], r["type"], d.get("provider"), d.get("status"), extra])
    console.print(f"\n[bold green]Dados exportados para {filename}[/bold green]")

@app.command()
def main(
    ioc: str = typer.Option(None, "--ioc", "-i"), 
    file: str = typer.Option(None, "--file", "-f"),
    export: str = typer.Option(None, "--export", "-e")
):
    providers = [
        VirusTotalProvider(settings.get("VT_API_KEY")),
        HybridAnalysisProvider(settings.get("HYBRID_API_KEY")),
        AlienVaultProvider(settings.get("OTX_API_KEY")),
        GreyNoiseProvider(settings.get("GREYNOISE_API_KEY")),
        AbuseIPDBProvider(settings.get("ABUSE_API_KEY")),
        GoogleSafeBrowsingProvider(settings.get("GOOGLE_API_KEY"))
    ]

    iocs_input = []
    if file:
        with open(file, 'r') as f: iocs_input = [l.strip() for l in f if l.strip()]
    elif ioc:
        iocs_input.append(ioc)
    else:
        console.print("Erro: Informe -i ou -f")
        return

    all_results = []
    for item in iocs_input:
        res = analyze_single_ioc(item, providers)
        if res: all_results.append(res)

    if export and all_results:
        export_data(all_results, export.lower())

if __name__ == "__main__":
    app()