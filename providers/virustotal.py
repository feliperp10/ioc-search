import requests
from .base import BaseProvider

class VirusTotalProvider(BaseProvider):
    """
    Implementação específica para a API v3 do VirusTotal.
    Capaz de consultar IPs, Domínios e Hashes.
    """

    def __init__(self, api_key: str):
        # Chama o construtor da classe pai (BaseProvider)
        super().__init__(api_key)
        # Define a URL base da API v3
        self.base_url = "https://www.virustotal.com/api/v3"
        # Configura o cabeçalho de autenticação padrão do VT
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def fetch(self, ioc: str, ioc_type: str):
        """
        Realiza a consulta ao VirusTotal baseada no tipo de IOC.
        """
        # Mapeamento simples: no VT, IPs vão para /ip_addresses, domínios para /domains, etc.
        endpoints = {
            "ip": "ip_addresses",
            "domain": "domains",
            "md5": "files",
            "sha256": "files"
        }

        endpoint = endpoints.get(ioc_type)
        if not endpoint:
            return {"error": f"Tipo de IOC '{ioc_type}' não suportado pelo VirusTotal."}

        url = f"{self.base_url}/{endpoint}/{ioc}"

        try:
            # Faz a requisição GET
            response = requests.get(url, headers=self.headers)
            
            # Se o status for 404, o IOC não foi encontrado na base deles
            if response.status_code == 404:
                return {"status": "not_found", "message": "IOC não encontrado na base do VT."}
            
            # Garante que a requisição foi bem sucedida (status 200)
            response.raise_for_status()
            
            # Retorna o JSON processado
            return self.normalize_results(response.json())

        except requests.exceptions.RequestException as e:
            return {"error": f"Falha na comunicação com VirusTotal: {str(e)}"}

    def normalize_results(self, raw_data: dict) -> dict:
        """
        Extrai apenas o que importa para um analista de SOC:
        O número de engines que detectaram o IOC como malicioso.
        """
        # Navega no JSON complexo do VT para pegar o resumo das análises
        attributes = raw_data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "provider": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0)
        }