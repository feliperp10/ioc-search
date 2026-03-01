import requests
from .base import BaseProvider

class GoogleSafeBrowsingProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.api_key = api_key.strip()

    def fetch(self, ioc: str, ioc_type: str):
        # O Google Safe Browsing foca prioritariamente em URLs e Domínios
        if ioc_type not in ["url", "domain"]:
            return {"status": "skipped", "provider": "GoogleSafeBrowsing"}

        # Se for domínio, formatamos como URL para a API aceitar
        url_to_check = ioc if ioc_type == "url" else f"http://{ioc}"

        payload = {
            "client": {
                "clientId": "threatscout-cli",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_to_check}]
            }
        }

        try:
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=15
            )
            
            if response.status_code != 200:
                return {"provider": "GoogleSafeBrowsing", "error": f"HTTP {response.status_code}"}

            data = response.json()
            
            # Se 'matches' não existir no JSON, o site é considerado seguro pelo Google
            matches = data.get("matches", [])
            
            if not matches:
                return {"provider": "GoogleSafeBrowsing", "status": "not_found", "verdict": "clean"}

            return self.normalize_results(matches[0])

        except Exception as e:
            return {"provider": "GoogleSafeBrowsing", "error": str(e)}

    def normalize_results(self, data: dict) -> dict:
        threat_type = data.get("threatType", "UNKNOWN")
        return {
            "provider": "GoogleSafeBrowsing",
            "verdict": "malicious",
            "threat_type": threat_type,
            "platform": data.get("platformType", "ALL")
        }