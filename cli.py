import typer
from concurrent.futures import ThreadPoolExecutor, as_completed
from validators import identify_ioc_type
from config import Config
from providers.virustotal import VirusTotalProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.greynoise import GreyNoiseProvider
from providers.alienvault import AlienVaultProvider

app = typer.Typer(help="ioc-search: Consulta de Threat Intelligence")

def run_provider(provider, ioc, ioc_type):
    return provider.fetch(ioc, ioc_type)

@app.command()
def search(ioc: str):
    ioc_type = identify_ioc_type(ioc)
    
    if ioc_type == "unknown":
        typer.secho(f"[-] Erro: IOC '{ioc}' não reconhecido.", fg=typer.colors.RED, bold=True)
        return

    typer.secho(f"[*] Analisando {ioc_type}: {ioc}", fg=typer.colors.BLUE, bold=True)

    # 1. Certifique-se de que os nomes no Config.XXXX batem com o seu config.py
    providers = [
        VirusTotalProvider(Config.VT_API_KEY),
        AbuseIPDBProvider(Config.ABUSE_API_KEY),
        GreyNoiseProvider(Config.GREYNOISE_API_KEY),
        AlienVaultProvider(Config.OTX_API_KEY)
    ]

    results = []
    with ThreadPoolExecutor(max_workers=len(providers)) as executor:
        future_to_provider = {executor.submit(run_provider, p, ioc, ioc_type): p for p in providers}
        
        for future in as_completed(future_to_provider):
            try:
                data = future.result()
                results.append(data)
            except Exception as exc:
                typer.secho(f"[!] Erro inesperado em um provider: {exc}", fg=typer.colors.RED)

    # --- EXIBIÇÃO ---
    for res in results:
        if "error" in res:
            typer.secho(f"\n[!] Erro em {res.get('provider')}: {res['error']}", fg=typer.colors.RED)
            continue
        
        if res.get("status") == "skipped":
            continue

        typer.echo("-" * 30)
        typer.secho(f"Provider: {res['provider']}", bold=True, fg=typer.colors.MAGENTA)

        if res['provider'] == "VirusTotal":
            malicioso = res.get('malicious', 0)
            cor = typer.colors.GREEN if malicioso == 0 else typer.colors.RED
            typer.secho(f"Deteções Maliciosas: {malicioso}", fg=cor, bold=True)

        elif res['provider'] == "AbuseIPDB":
            score = res.get('abuse_score', 0)
            cor = typer.colors.RED if score > 50 else typer.colors.GREEN
            typer.secho(f"Confiança de Abuso: {score}%", fg=cor, bold=True)

        elif res['provider'] == "GreyNoise":
            cor = typer.colors.YELLOW if res.get('is_noise') else typer.colors.GREEN
            typer.secho(f"É Ruído (Noise): {res.get('is_noise')}", fg=cor)
            typer.echo(f"Classificação: {res.get('classification')}")

        elif res['provider'] == "AlienVault":
            count = res.get('pulses', 0)
            cor = typer.colors.RED if count > 0 else typer.colors.GREEN
            typer.secho(f"Pulses no OTX: {count}", fg=cor, bold=True)

    typer.echo("-" * 30)

if __name__ == "__main__":
    app()