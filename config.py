import os
from dotenv import load_dotenv

# Carrega as variáveis do arquivo .env
load_dotenv()

class Config:
    """
    Centraliza as chaves seguindo os nomes exatos do seu .env
    """
    # Nomes atualizados conforme sua lista
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
    GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
    HYBRID_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

    @classmethod
    def validate_config(cls):
        """Validador para nos ajudar no debug"""
        if not cls.VT_API_KEY:
            print("[!] Alerta: VIRUSTOTAL_API_KEY não encontrada.")
        else:
            print(f"[*] Configuração carregada com sucesso para: VIRUSTOTAL_API_KEY")