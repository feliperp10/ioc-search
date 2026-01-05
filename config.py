import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    OTX_API_KEY = os.getenv("ALIENVAULT_API_KEY")
    GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
    HYBRID_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")