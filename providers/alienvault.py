import requests
from .base import BaseProvider

class AlienVaultProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"
        self.headers = {
            "X-OTX-API-KEY": self.api_key.strip(),
            "Accept": "application/json"
        }

    def fetch(self, ioc: str, ioc_type: str):
        # Mapeamento dinâmico para garantir que os 3 tipos funcionem
        tipo_otx = {
            "hash": "file",
            "sha256": "file",
            "md5": "file",
            "sha1": "file",
            "ip": "IPv4",
            "domain": "domain",
            "url": "url"
        }.get(ioc_type)

        if not tipo_otx:
            return {"status": "skipped", "provider": "AlienVault"}

        try:
            # O endpoint /general é o que traz o resumo de Pulses e Tags
            url = f"{self.base_url}/{tipo_otx}/{ioc}/general"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 404:
                return {"provider": "AlienVault", "status": "not_found"}
            
            response.raise_for_status()
            return self.normalize_results(response.json())
        except Exception as e:
            return {"provider": "AlienVault", "error": str(e)}

    def normalize_results(self, raw_data: dict) -> dict:
        pulse_info = raw_data.get("pulse_info", {})
        count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        
        # Coleta tags de todos os pulses retornados e remove duplicatas
        all_tags = []
        for p in pulses:
            tags = p.get("tags", [])
            if tags:
                all_tags.extend(tags)
        
        # Limpa e limita a exibição às 4 tags mais relevantes
        unique_tags = sorted(list(set(all_tags)), key=len, reverse=True)[:4]
        tag_str = ", ".join(unique_tags) if unique_tags else "Sem tags específicas"

        return {
            "provider": "AlienVault",
            "pulses_count": count,
            "details": f"Presente em {count} campanhas | Tags: {tag_str}"
        }