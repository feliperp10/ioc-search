import requests

class GoogleSafeBrowsingProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "SafeBrowsing"
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def fetch(self, ioc, ioc_type):
        if ioc_type != "url":
            return {"provider": self.name, "status": "skipped"}
        
        if not self.api_key:
            return {"provider": self.name, "status": "error", "error": "Missing Google API Key"}

        payload = {
            "client": {"clientId": "ioc-search", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": ioc}]
            }
        }
        
        try:
            r = requests.post(f"{self.base_url}?key={self.api_key}", json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                matches = data.get("matches", [])
                if matches:
                    return {"provider": self.name, "status": "success", "verdict": matches[0]["threatType"]}
                return {"provider": self.name, "status": "success", "verdict": "SAFE"}
            return {"provider": self.name, "status": "error", "error": f"API Error: {r.status_code}"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}