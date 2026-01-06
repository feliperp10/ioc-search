import requests
from .base import BaseProvider

class HybridAnalysisProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key.strip(),
            "user-agent": "Falcon Sandbox",
            "Accept": "application/json"
        }

    def fetch(self, ioc: str, ioc_type: str):
        """Busca informacoes usando search/hash com tratamento para erro 400."""
        if ioc_type not in ["hash", "sha256", "md5"]:
            return {"status": "skipped", "provider": "HybridAnalysis"}

        try:
            url = f"{self.base_url}/search/hash"
            
            # O Hybrid Analysis as vezes exige que os dados sejam passados como form-data
            payload = {'hash': ioc}
            
            # Usamos o parametro 'data' em vez de 'json' para enviar como form-data
            response = requests.post(url, headers=self.headers, data=payload, timeout=15)
            
            if response.status_code == 404:
                return {"provider": "HybridAnalysis", "status": "not_found"}
            
            # Se ainda der 400, tentamos uma alternativa via GET (overview)
            if response.status_code == 400:
                url_get = f"{self.base_url}/overview/{ioc}"
                response = requests.get(url_get, headers=self.headers, timeout=15)

            response.raise_for_status()
            data = response.json()
            
            # A resposta do search e uma lista, a do overview e um dict
            report = data[0] if isinstance(data, list) else data
            return self.normalize_results(report)

        except Exception as e:
            return {"provider": "HybridAnalysis", "error": f"Status {getattr(e.response, 'status_code', 'ERRO')}: {str(e)}"}

    def normalize_results(self, data: dict) -> dict:
        """Extrai indicadores de comportamento da sandbox."""
        # Tenta capturar a lista de indicadores de ameaca
        indicators = data.get("threat_indicators", [])
        
        return {
            "provider": "HybridAnalysis",
            "threat_score": data.get("threat_score", 0),
            "verdict": data.get("verdict", "unknown"),
            "vx_family": data.get("vx_family", "N/A"),
            "env": data.get("environment_description", "N/A"),
            "indicators_count": len(indicators) if isinstance(indicators, list) else 0
        }