import os
from pathlib import Path
from dotenv import load_dotenv

class Config:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent
        env_path = base_dir / ".env"
        # override=True é vital para não usar lixo da memória do terminal
        load_dotenv(dotenv_path=env_path, override=True)

    def get(self, key):
        value = os.getenv(key)
        if value:
            # Limpeza radical: remove espaços, aspas simples/duplas e quebras de linha
            return value.strip().replace('"', '').replace("'", "").replace("\n", "").replace("\r", "")
        return ""

settings = Config()