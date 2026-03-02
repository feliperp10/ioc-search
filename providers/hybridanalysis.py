import requests

class HybridAnalysisProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "HybridAnalysis"
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def fetch(self, ioc, ioc_type):
        if ioc_type not in ["md5", "sha1", "sha256"]:
            return {"provider": self.name, "status": "skipped"}

        headers = {"api-key": self.api_key, "user-agent": "Falcon Sandbox", "Accept": "application/json"}
        params = {"hash": ioc}

        try:
            response = requests.get(f"{self.base_url}/search/hash", headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                reports = response.json().get("reports", [])
                if reports:
                    valid_report = next((r for r in reports if r.get("verdict")), reports[0])
                    return {
                        "provider": self.name,
                        "status": "success",
                        "verdict": valid_report.get("verdict", "unknown"),
                        "score": valid_report.get("threat_score", "N/A")
                    }
                return {"provider": self.name, "status": "error", "error": "No reports found"}
            return {"provider": self.name, "status": "error", "error": f"Status {response.status_code}"}
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}