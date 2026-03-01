import requests

class AbuseIPDBProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "AbuseIPDB"
        self.url = "https://api.abuseipdb.com/api/v2/check"

    def fetch(self, ioc, ioc_type):
        # CORREÇÃO: Deve validar 'ipv4'
        if ioc_type != "ipv4":
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
            response = requests.get(self.url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "provider": self.name,
                    "status": "success",
                    "score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "isp": data.get("isp", "N/A"),
                    "country": data.get("countryCode", "N/A")
                }
            return {"provider": self.name, "status": "error"}
        except Exception as e:
            raise Exception(f"Erro na API AbuseIPDB: {str(e)}")