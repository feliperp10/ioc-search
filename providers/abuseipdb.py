import requests

from providers.base import BaseProvider


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    supported_types = ["ipv4", "ipv6"]
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def _query(self, ioc, ioc_type):
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc, "maxAgeInDays": 90}

        resp = requests.get(self.BASE_URL, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "verdict": score,
            "confidence": score,
            "isp": data.get("isp"),
            "asn": data.get("asn"),
        }
