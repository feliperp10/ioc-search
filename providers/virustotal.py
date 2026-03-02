import requests
import base64

class VirusTotalProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "VirusTotal"
        self.base_url = "https://www.virustotal.com/api/v3"

    def fetch(self, ioc, ioc_type):
        if ioc_type in ["ipv4", "ipv6"]:
            endpoint = f"{self.base_url}/ip_addresses/{ioc}"
        elif ioc_type in ["md5", "sha1", "sha256"]:
            endpoint = f"{self.base_url}/files/{ioc}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
        else:
            return {"provider": self.name, "status": "skipped"}

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(endpoint, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                return {
                    "provider": self.name,
                    "status": "success",
                    "verdict": stats.get("malicious", 0),
                    "asn": data.get("asn"),
                    "as_owner": data.get("as_owner")
                }
            return {"provider": self.name, "status": "error", "error": "Not found or API limit"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}