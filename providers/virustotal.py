import requests
from .base import BaseProvider

class VirusTotalProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    def fetch(self, ioc: str, ioc_type: str):
        # Mapeamento estrito conforme Documentação V3
        tipo_endpoint = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "sha256": "files",
            "md5": "files"
        }.get(ioc_type)

        if not tipo_endpoint:
            return {"status": "skipped", "provider": "VirusTotal"}

        # Cabeçalhos conforme o padrão VirusTotal v3
        headers = {
            "x-apikey": str(self.api_key).strip(),
            "accept": "application/json"
        }

        try:
            url = f"{self.base_url}/{tipo_endpoint}/{ioc}"
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 404:
                return {"provider": "VirusTotal", "status": "not_found", "message": "IOC não encontrado na base."}
            
            # Se der 401 aqui, a chave no .env está inválida para o VT
            response.raise_for_status()
            
            return self.normalize_results(response.json())
        except Exception as e:
            return {"provider": "VirusTotal", "error": str(e)}

    def normalize_results(self, raw_data: dict) -> dict:
        # Extração precisa dos dados de análise
        attr = raw_data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        
        return {
            "provider": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": attr.get("reputation", 0),
            "type": attr.get("type_description", "N/A")
        }