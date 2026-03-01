import requests

class VirusTotalProvider:
    def __init__(self, api_key):
        self.api_key = api_key
        self.name = "VirusTotal"
        self.base_url = "https://www.virustotal.com/api/v3"

    def fetch(self, ioc, ioc_type):
        """
        Consulta a API v3 do VirusTotal para extrair reputacao, 
        detecoes e informacoes de infraestrutura (ASN/Owner).
        """
        # Mapeamento de endpoints por tipo de recurso
        endpoints = {
            "ipv4": f"{self.base_url}/ip_addresses/{ioc}",
            "domain": f"{self.base_url}/domains/{ioc}",
            "url": f"{self.base_url}/urls/{requests.utils.quote(ioc, safe='')}",
            "md5": f"{self.base_url}/files/{ioc}",
            "sha1": f"{self.base_url}/files/{ioc}",
            "sha256": f"{self.base_url}/files/{ioc}"
        }

        if ioc_type not in endpoints:
            return {"provider": self.name, "status": "skipped"}

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(endpoints[ioc_type], headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                # Extração de campos de infraestrutura (específicos para IP e Domínio)
                return {
                    "provider": self.name,
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "reputation": attributes.get("reputation", 0),
                    "type": attributes.get("type_description", ioc_type),
                    # Novos campos solicitados
                    "asn": attributes.get("asn", "N/A"),
                    "as_owner": attributes.get("as_owner", "N/A"),
                    "tags": attributes.get("tags", [])
                }
            
            elif response.status_code == 404:
                return {"provider": self.name, "status": "not_found"}
            
            elif response.status_code == 401:
                return {"provider": self.name, "error": "Chave de API invalida"}
            
            else:
                return {"provider": self.name, "error": f"Erro HTTP {response.status_code}"}

        except requests.exceptions.Timeout:
            return {"provider": self.name, "error": "Timeout na comunicacao"}
        except Exception as e:
            return {"provider": self.name, "error": str(e)}