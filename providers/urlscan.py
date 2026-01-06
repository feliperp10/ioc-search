import requests
from .base import BaseProvider

class URLScanProvider(BaseProvider):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://urlscan.io/api/v1/search/"
        self.headers = {"API-Key": self.api_key}

    def fetch(self, ioc: str, ioc_type: str):
        # O URLScan aceita buscas por IP, Domínio ou URL
        query = f"page.domain:\"{ioc}\" OR page.ip:\"{ioc}\" OR page.url:\"{ioc}\""
        
        try:
            params = {"q": query, "size": 1}
            response = requests.get(self.base_url, headers=self.headers, params=params)
            
            if response.status_code == 401:
                return {"error": "Chave API Inválida", "provider": "URLScan"}
                
            response.raise_for_status()
            return self.normalize_results(response.json())
        except Exception as e:
            return {"error": str(e), "provider": "URLScan"}

    def normalize_results(self, raw_data: dict) -> dict:
        results = raw_data.get("results", [])
        if not results:
            return {"provider": "URLScan", "status": "not_found", "message": "Sem histórico."}
        
        last = results[0]
        return {
            "provider": "URLScan",
            "date": last.get("task", {}).get("time"),
            "url": last.get("task", {}).get("url"),
            "report": last.get("result"),
            "country": last.get("page", {}).get("country")
        }