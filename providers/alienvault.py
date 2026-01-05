import requests
from .base import BaseProvider

class AlienVaultProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def fetch(self, ioc: str, ioc_type: str):
        # Mapeamento para os endpoints do OTX
        type_map = {"ip": "IPv4", "domain": "domain", "url": "url"}
        otx_type = type_map.get(ioc_type)

        if not otx_type:
            return {"status": "skipped", "message": "OTX não suporta este tipo de IOC."}

        try:
            response = requests.get(f"{self.base_url}/{otx_type}/{ioc}/general", headers=self.headers)
            response.raise_for_status()
            return self.normalize_results(response.json())
        except Exception as e:
            return {"error": str(e), "provider": "AlienVault"}

    def normalize_results(self, raw_data: dict) -> dict:
        pulse_info = raw_data.get("pulse_info", {})
        return {
            "provider": "AlienVault",
            "pulses": pulse_info.get("count", 0),
            "tags": list(set(tag for p in pulse_info.get("pulses", []) for tag in p.get("tags", [])))[:5]
        }