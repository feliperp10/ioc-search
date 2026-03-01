import requests

class HybridAnalysisProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "HybridAnalysis"
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def fetch(self, ioc, ioc_type):
        if ioc_type not in ["md5", "sha1", "sha256"]:
            return {"provider": self.name, "status": "skipped"}

        # Endpoint de busca por hash
        endpoint = f"{self.base_url}/search/hash"
        
        headers = {
            "api-key": self.api_key,
            "user-agent": "Falcon Sandbox", # Obrigatorio para esta API
            "Accept": "application/json"
        }
        
        # Enviando como query parameters (costuma ser mais aceito que o body em POST v2)
        params = {"hash": ioc}

        try:
            # Algumas implementacoes do Hybrid Analysis v2 exigem POST, mas aceitam os dados via params
            response = requests.post(endpoint, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                res_data = response.json()
                
                if isinstance(res_data, list) and len(res_data) > 0:
                    # Pegamos a analise mais relevante
                    analysis = res_data[0]
                    verdict = analysis.get("verdict", "unknown")
                    score = analysis.get("threat_score", 0)
                    
                    return {
                        "provider": self.name,
                        "status": "success",
                        "verdict": verdict,
                        "score": score,
                        "malicious": 1 if verdict in ["malicious", "suspicious"] else 0
                    }
                return {"provider": self.name, "status": "not_found"}
            
            # Caso a API retorne erro, passamos o status para o CLI
            return {"provider": self.name, "error": f"Status {response.status_code}"}

        except Exception as e:
            return {"provider": self.name, "error": str(e)}