import requests
from .base import BaseProvider

class AbuseIPDBProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def fetch(self, ioc: str, ioc_type: str):
        if ioc_type != "ip":
            return {"status": "skipped", "provider": "AbuseIPDB"}

        headers = {
            "Accept": "application/json",
            "Key": self.api_key.strip()
        }
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": "90"
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params, timeout=15)
            response.raise_for_status()
            return self.normalize_results(response.json())
        except Exception as e:
            return {"provider": "AbuseIPDB", "error": str(e)}

    def normalize_results(self, raw_data: dict) -> dict:
        data = raw_data.get("data", {})
        return {
            "provider": "AbuseIPDB",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "isp": data.get("isp", "Desconhecido"),
            "country": data.get("countryCode", "N/A"),
            "usage": data.get("usageType", "N/A"),
            "reports": data.get("totalReports", 0)
        }