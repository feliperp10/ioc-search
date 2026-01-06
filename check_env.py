import os
from pathlib import Path
from dotenv import load_dotenv

print(f"Diretório atual de execução: {os.getcwd()}")
print(f"O arquivo .env existe aqui? {os.path.exists('.env')}")

# Tenta carregar
load_dotenv(override=True)
print(f"VT_API_KEY carregada: {'Sim' if os.getenv('VT_API_KEY') else 'Não'}")