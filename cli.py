import typer
from concurrent.futures import ThreadPoolExecutor, as_completed
from validators import identify_ioc_type
from config import Config
from providers.virustotal import VirusTotalProvider
from providers.abuseipdb import AbuseIPDBProvider

app = typer.Typer(help="ioc-search: Consulta de Threat Intelligence")

def run_provider(provider, ioc, ioc_type):
    """Função auxiliar para ser executada em paralelo"""
    return provider.fetch(ioc, ioc_type)

@app.command()
def search(ioc: str):
    """
    Pesquisa um IOC em múltiplos provedores SIMULTANEAMENTE.
    """
    ioc_type = identify_ioc_type(ioc)
    
    if ioc_type == "unknown":
        typer.secho(f"[-] Erro: IOC '{ioc}' não reconhecido.", fg=typer.colors.RED, bold=True)
        return

    typer.secho(f"[*] Analisando {ioc_type}: {ioc}", fg=typer.colors.BLUE, bold=True)

    # Lista de instâncias dos providers
    providers = [
        VirusTotalProvider(Config.VT_API_KEY),
        AbuseIPDBProvider(Config.ABUSE_API_KEY)
    ]

    # --- MÁGICA DO PARALELISMO ---
    results = []
    with ThreadPoolExecutor(max_workers=len(providers)) as executor:
        # Dispara as tarefas para todos os providers ao mesmo tempo
        future_to_provider = {executor.submit(run_provider, p, ioc, ioc_type): p for p in providers}
        
        for future in as_completed(future_to_provider):
            try:
                data = future.result()
                results.append(data)
            except Exception as exc:
                typer.secho(f"[!] Erro inesperado: {exc}", fg=typer.colors.RED)

    # --- EXIBIÇÃO ---
    for res in results:
        if "error" in res:
            typer.secho(f"\n[!] Erro em {res.get('provider', 'Desconhecido')}: {res['error']}", fg=typer.colors.RED)
            continue
        
        if res.get("status") == "skipped":
            continue

        typer.echo("-" * 30)
        typer.secho(f"Provider: {res['provider']}", bold=True, fg=typer.colors.MAGENTA)

        if res['provider'] == "VirusTotal":
            malicioso = res.get('malicious', 0)
            cor = typer.colors.GREEN if malicioso == 0 else typer.colors.RED
            typer.secho(f"Deteções Maliciosas: {malicioso}", fg=cor, bold=True)
            typer.echo(f"Reputação: {res.get('reputation')}")

        elif res['provider'] == "AbuseIPDB":
            score = res.get('abuse_score', 0)
            cor = typer.colors.RED if score > 50 else typer.colors.GREEN
            typer.secho(f"Confiança de Abuso: {score}%", fg=cor, bold=True)
            typer.echo(f"País: {res.get('country')}")

    typer.echo("-" * 30)

if __name__ == "__main__":
    app()