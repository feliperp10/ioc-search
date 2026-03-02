import requests

class HybridAnalysisProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "HybridAnalysis"
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def fetch(self, ioc, ioc_type):
        if ioc_type not in ["md5", "sha1", "sha256"]:
            return {"provider": self.name, "status": "skipped"}

        endpoint = f"{self.base_url}/search/hash"
        headers = {
            "api-key": self.api_key,
            "user-agent": "Falcon Sandbox",
            "Accept": "application/json"
        }
        
        # Conforme sua imagem: hash é um query parameter e o método é GET
        params = {"hash": ioc}

        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                res_data = response.json()
                
                # Ajuste baseado no seu JSON: A API retorna um objeto com uma lista 'reports'
                reports = res_data.get("reports", [])
                
                if isinstance(reports, list) and len(reports) > 0:
                    # Procuramos o primeiro relatório que tenha um veredito válido (não nulo)
                    valid_report = next((r for r in reports if r.get("verdict")), reports[0])
                    
                    verdict = valid_report.get("verdict", "unknown")
                    # O seu JSON mostra 'malicious' em vários relatórios de sucesso
                    
                    return {
                        "provider": self.name,
                        "status": "success",
                        "verdict": verdict,
                        "score": valid_report.get("threat_score", "N/A"), # Se houver score
                        "malicious": 1 if verdict in ["malicious", "suspicious"] else 0
                    }
                
                return {"provider": self.name, "status": "not_found"}
            
            return {"provider": self.name, "error": f"Status {response.status_code}"}

        except Exception as e:
            return {"provider": self.name, "error": str(e)}