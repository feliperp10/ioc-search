import requests

class GreyNoiseProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "GreyNoise"
        self.url = "https://api.greynoise.io/v3/community"

    def fetch(self, ioc, ioc_type):
        # GreyNoise Community API só aceita IPv4
        if ioc_type != "ipv4":
            return {"provider": self.name, "status": "skipped"}

        headers = {"key": self.api_key}
        try:
            response = requests.get(f"{self.url}/{ioc}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "provider": self.name,
                    "status": "success",
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False), # RIOT indica IPs de serviços comuns (Google, MSFT)
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", "Desconhecido")
                }
            return {"provider": self.name, "status": "not_found"}
        except Exception as e:
            raise Exception(f"Erro GreyNoise: {str(e)}")