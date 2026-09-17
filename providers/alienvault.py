from urllib.parse import quote
import requests

from providers.base import BaseProvider


class AlienVaultProvider(BaseProvider):
    name = "AlienVault"
    supported_types = ["ipv4", "ipv6", "url", "md5", "sha1", "sha256"]
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def _headers(self):
        return {"X-OTX-API-KEY": self.api_key}

    def _query(self, ioc, ioc_type):
        if ioc_type == "ipv4":
            endpoint = f"{self.BASE_URL}/IPv4/{ioc}/general"
        elif ioc_type == "ipv6":
            endpoint = f"{self.BASE_URL}/IPv6/{ioc}/general"
        elif ioc_type == "url":
            if "://" in ioc:
                encoded = quote(ioc, safe="")
                endpoint = f"{self.BASE_URL}/url/{encoded}/general"
            else:
                endpoint = f"{self.BASE_URL}/domain/{ioc}/general"
        else:  # md5 / sha1 / sha256
            endpoint = f"{self.BASE_URL}/file/{ioc}/general"

        resp = requests.get(endpoint, headers=self._headers(), timeout=15)
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)

        return {
            "verdict": pulse_count,
            "pulse_count": pulse_count,
        }
