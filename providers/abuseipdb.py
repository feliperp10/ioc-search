import requests

class AbuseIPDBProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "AbuseIPDB"
        self.url = "https://api.abuseipdb.com/api/v2/check"

    def fetch(self, ioc, ioc_type):
        if ioc_type not in ["ipv4", "ipv6"]:
            return {"provider": self.name, "status": "skipped"}

        if not self.api_key:
            return {"provider": self.name, "status": "error", "error": "Missing API Key"}

        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ioc, "maxAgeInDays": "90"}

        try:
            response = requests.get(self.url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "provider": self.name,
                    "status": "success",
                    "verdict": score,
                    "confidence": score,
                    "isp": data.get("isp"),
                    "asn": data.get("asn")
                }
            elif response.status_code == 429:
                return {"provider": self.name, "status": "error", "error": "Rate Limit exceeded"}
            return {"provider": self.name, "status": "error", "error": f"HTTP Error {response.status_code}"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}