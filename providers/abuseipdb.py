import requests
from .base import BaseProvider

class AbuseIPDBProvider(BaseProvider):
    """
    Provider para a API do AbuseIPDB.
    Focado em reputação de IP baseada em denúncias de comportamentos maliciosos.
    """

    def __init__(self, api_key: str):
        # Inicializa a classe base com a sua chave de API
        super().__init__(api_key)
        # Endpoint oficial da API v2 para checagem de IP
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        # O AbuseIPDB exige a chave no cabeçalho 'Key'
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def fetch(self, ioc: str, ioc_type: str):
        """
        Executa a consulta. AbuseIPDB só suporta IPs.
        """
        # Regra de negócio: se não for IP, este provider não é acionado
        if ioc_type != "ip":
            return {"status": "skipped", "message": "AbuseIPDB suporta apenas IPs."}

        # Parâmetros da consulta conforme documentação oficial
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": "90"  # Busca denúncias dos últimos 90 dias
        }

        try:
            # Realiza a requisição HTTP GET
            response = requests.get(self.base_url, headers=self.headers, params=params)
            
            # Se retornar erro (ex: 401 ou 429), levanta uma exceção
            response.raise_for_status()
            
            # Se der certo, normaliza os dados antes de retornar
            return self.normalize_results(response.json())
            
        except requests.exceptions.RequestException as e:
            # Retorna o erro de forma que o cli.py saiba tratar
            return {"error": f"Erro na API AbuseIPDB: {str(e)}", "provider": "AbuseIPDB"}

    def normalize_results(self, raw_data: dict) -> dict:
        """
        Extrai apenas os dados relevantes para o analista de segurança.
        """
        data = raw_data.get("data", {})
        
        return {
            "provider": "AbuseIPDB",
            "abuse_score": data.get("abuseConfidenceScore", 0), # Confiança de que é malicioso (0-100)
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "??"),
            "domain": data.get("domain", "N/A"),
            "last_report": data.get("lastReportedAt", "N/A")
        }