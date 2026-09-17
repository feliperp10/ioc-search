import base64
import requests

from providers.base import BaseProvider


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    supported_types = ["ipv4", "ipv6", "url", "md5", "sha1", "sha256"]
    BASE_URL = "https://www.virustotal.com/api/v3"

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _query(self, ioc, ioc_type):
        if ioc_type in ("ipv4", "ipv6"):
            endpoint = f"{self.BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "url":
            if "://" in ioc:
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                endpoint = f"{self.BASE_URL}/urls/{url_id}"
            else:
                endpoint = f"{self.BASE_URL}/domains/{ioc}"
        else:  # md5 / sha1 / sha256
            endpoint = f"{self.BASE_URL}/files/{ioc}"

        resp = requests.get(endpoint, headers=self._headers(), timeout=15)

        if resp.status_code == 404:
            return {"verdict": 0, "malicious": 0, "note": "Não encontrado na base do VirusTotal"}

        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        result = {
            "verdict": malicious + suspicious,
            "malicious": malicious,
        }

        if ioc_type in ("ipv4", "ipv6"):
            result["as_owner"] = attrs.get("as_owner")
            result["asn"] = attrs.get("asn")

        return result
