import requests

class AlienVaultProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "AlienVault"
        self.url = "https://otx.alienvault.com/api/v1/indicators"

    def fetch(self, ioc, ioc_type):
        otx_type_map = {"ipv4": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha256": "file"}
        if ioc_type not in otx_type_map:
            return {"provider": self.name, "status": "skipped"}

        headers = {"X-OTX-API-KEY": self.api_key}
        endpoint = f"{self.url}/{otx_type_map[ioc_type]}/{ioc}/general"

        try:
            response = requests.get(endpoint, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get("pulse_info", {}).get("pulses", [])
                return {
                    "provider": self.name,
                    "status": "success",
                    "pulse_count": len(pulses), # Corrigido para bater com cli.py
                    "verdict": "INFO"
                }
            return {"provider": self.name, "status": "error", "error": "Indicator not found"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}