from config import Config
from providers.virustotal import VirusTotalProvider

# 1. Valida se carregou do .env
Config.validate_config()

# 2. Instancia o provider
vt = VirusTotalProvider(Config.VT_API_KEY)

# ... resto do código de teste