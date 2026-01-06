import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import settings
from validators import identify_ioc_type
from providers.virustotal import VirusTotalProvider
from providers.alienvault import AlienVaultProvider
from providers.urlscan import URLScanProvider
from providers.hybridanalysis import HybridAnalysisProvider

app = typer.Typer()
console = Console()

def run_provider(provider, ioc, ioc_type):
    try:
        return provider.fetch(ioc, ioc_type)
    except Exception as e:
        return {"provider": provider.__class__.__name__.replace("Provider", ""), "error": str(e)}

@app.command()
def search(ioc: str):
    ioc_type = identify_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print("[bold red]Erro:[/bold red] IOC Inválido.")
        return

    console.print(f"\n[*] Investigando: [bold cyan]{ioc}[/bold cyan]\n")

    providers = [
        VirusTotalProvider(settings.get("VT_API_KEY")),
        HybridAnalysisProvider(settings.get("HYBRID_API_KEY")),
        AlienVaultProvider(settings.get("OTX_API_KEY")),
        URLScanProvider(settings.get("URLSCAN_API_KEY"))
    ]

    table = Table(show_header=True, header_style="bold white on blue", expand=True, box=box.ROUNDED)
    table.add_column("Provider", width=18)
    table.add_column("Status / Resultado", justify="center", width=22)
    table.add_column("Detalhes e Contexto de Ameaça")

    with console.status("[bold green]Coletando Inteligência...[/bold green]"):
        with ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = {executor.submit(run_provider, p, ioc, ioc_type): p for p in providers}
            
            for future in as_completed(futures):
                res = future.result()
                if not res or res.get("status") == "skipped": continue
                
                nome = res.get("provider", "Desconhecido")
                
                if "error" in res:
                    table.add_row(nome, "[bold red]FALHA[/bold red]", f"[red]{res['error']}[/red]")
                elif res.get("status") == "not_found":
                    table.add_row(nome, "[bold yellow]LIMPO / NF[/bold yellow]", "Sem registros encontrados nesta base.")
                else:
                    # Lógica para Hybrid Analysis (Baseado no seu JSON)
                    if nome == "HybridAnalysis":
                        v = res.get('verdict', 'unknown').upper()
                        score = res.get('threat_score', 0)
                        cor = "bright_red" if v == "MALICIOUS" else "bright_yellow" if v == "SUSPICIOUS" else "green"
                        
                        status = Text(f"Score: {score}/100", style=f"bold {cor}")
                        detalhes = Text.assemble(
                            ("Veredito: ", "white"), (v, f"bold {cor}"),
                            (" | Ambiente: ", "white"), (f"{res.get('env', 'N/A')}", "italic cyan"),
                            (" | Job: ", "white"), (f"{res.get('job_id', 'N/A')[:10]}", "dim")
                        )
                        table.add_row(nome, status, detalhes)
                    
                    # Lógica para VirusTotal
                    elif nome == "VirusTotal":
                        det = res.get('malicious', 0)
                        cor = "bright_red" if det > 0 else "green"
                        status = Text(f"{det} Detecções", style=f"bold {cor}")
                        table.add_row(nome, status, f"Tipo: {res.get('type')} | Reputação: {res.get('reputation')}")

                    # Lógica para AlienVault
                    elif nome == "AlienVault":
                        cnt = res.get('pulses_count', 0)
                        cor = "bright_red" if cnt > 0 else "green"
                        status = Text(f"{cnt} Pulses", style=f"bold {cor}")
                        table.add_row(nome, status, res.get('details', 'N/A'))

                    # Lógica Genérica
                    else:
                        table.add_row(nome, "[green]Concluído[/green]", "Análise finalizada com sucesso.")

                table.add_section()

    console.print(table)
    console.print("\n[dim]* Pesquisa baseada em APIs de Threat Intelligence pública/comunidade.[/dim]")

if __name__ == "__main__":
    app()