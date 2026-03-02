import requests

class VirusTotalProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "VirusTotal"
        self.base_url = "https://www.virustotal.com/api/v3"

    def fetch(self, ioc, ioc_type):
        # Aceita IPv4 e IPv6
        if ioc_type == "ipv4" or ioc_type == "ipv6":
            endpoint = f"{self.base_url}/ip_addresses/{ioc}"
        elif ioc_type in ["md5", "sha1", "sha256"]:
            endpoint = f"{self.base_url}/files/{ioc}"
        elif ioc_type == "url":
            import base64
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
                    "malicious": stats.get("malicious", 0),
                    "reputation": data.get("reputation", 0),
                    "asn": data.get("asn", "N/A"),
                    "as_owner": data.get("as_owner", "N/A")
                }
            return {"provider": self.name, "status": "not_found"}
        except Exception as e:
            return {"provider": self.name, "error": str(e)}