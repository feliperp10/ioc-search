import requests
from .base import BaseProvider

class GreyNoiseProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://api.greynoise.io/v3/community"
        self.headers = {"key": self.api_key, "Accept": "application/json"}

    def fetch(self, ioc: str, ioc_type: str):
        if ioc_type != "ip":
            return {"status": "skipped", "message": "GreyNoise suporta apenas IPs."}

        try:
            response = requests.get(f"{self.base_url}/{ioc}", headers=self.headers)
            if response.status_code == 404:
                return {"status": "not_found", "message": "IP não visto pelo GreyNoise."}
            response.raise_for_status()
            return self.normalize_results(response.json())
        except Exception as e:
            return {"error": str(e), "provider": "GreyNoise"}

    def normalize_results(self, raw_data: dict) -> dict:
        return {
            "provider": "GreyNoise",
            "is_noise": raw_data.get("noise", False),
            "is_riot": raw_data.get("riot", False),
            "classification": raw_data.get("classification", "unknown"),
            "name": raw_data.get("name", "N/A")
        }