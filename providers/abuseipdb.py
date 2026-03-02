import requests

class AbuseIPDBProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "AbuseIPDB"
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def fetch(self, ioc, ioc_type):
        # Valida se é IP (v4 ou v6)
        if ioc_type not in ["ipv4", "ipv6"]:
            return {"provider": self.name, "status": "skipped"}

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": "90"
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                res = response.json()["data"]
                return {
                    "provider": self.name,
                    "status": "success",
                    "score": res.get("abuseConfidenceScore", 0),
                    "isp": res.get("isp", "Desconhecido"),
                    "country": res.get("countryCode", "??"),
                    "usage_type": res.get("usageType", "N/A")
                }
            return {"provider": self.name, "status": "not_found"}
        except Exception as e:
            return {"provider": self.name, "error": str(e)}