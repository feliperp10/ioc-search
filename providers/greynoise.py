import requests

from providers.base import BaseProvider


class GreyNoiseProvider(BaseProvider):
    name = "GreyNoise"
    # API Community do GreyNoise só cobre IPv4
    supported_types = ["ipv4"]
    BASE_URL = "https://api.greynoise.io/v3/community"

    def _query(self, ioc, ioc_type):
        headers = {"key": self.api_key, "Accept": "application/json"}
        resp = requests.get(f"{self.BASE_URL}/{ioc}", headers=headers, timeout=15)

        if resp.status_code == 404:
            return {"verdict": "unknown", "note": "Sem dados na base GreyNoise"}

        resp.raise_for_status()
        data = resp.json()

        return {
            "verdict": data.get("classification", "unknown"),
            "noise": data.get("noise"),
            "riot": data.get("riot"),
        }
