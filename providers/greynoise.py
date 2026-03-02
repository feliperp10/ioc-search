import requests

class GreyNoiseProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "GreyNoise"
        self.base_url = "https://api.greynoise.io/v3/community"

    def fetch(self, ioc, ioc_type):
        if ioc_type not in ["ipv4", "ipv6"]:
            return {"provider": self.name, "status": "skipped"}
        
        if not self.api_key:
            return {"provider": self.name, "status": "error", "error": "Missing GreyNoise API Key"}

        headers = {"accept": "application/json", "key": self.api_key}
        try:
            response = requests.get(f"{self.base_url}/{ioc}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                classification = data.get("classification", "unknown")
                return {"provider": self.name, "status": "success", "verdict": classification}
            elif response.status_code == 404:
                return {"provider": self.name, "status": "success", "verdict": "NOT_FOUND"}
            return {"provider": self.name, "status": "error", "error": f"Error {response.status_code}"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}