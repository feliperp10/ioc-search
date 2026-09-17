#!/usr/bin/env python3
"""
Teste rápido de conectividade: confirma que a VT_API_KEY está configurada
e faz uma consulta simples (8.8.8.8) contra a API do VirusTotal.
Rode com: python3 test_api.py
"""
from config import settings
from providers.virustotal import VirusTotalProvider

# 1. Valida se a chave foi carregada do .env
vt_key = settings.get("VT_API_KEY")
if not vt_key:
    print("[ERRO] VT_API_KEY não encontrada. Confira seu arquivo .env.")
    raise SystemExit(1)

print("[OK] VT_API_KEY carregada com sucesso.")

# 2. Instancia o provider e faz uma consulta de teste
vt = VirusTotalProvider(vt_key)
result = vt.fetch("8.8.8.8", "ipv4")

print("Resultado da consulta de teste (8.8.8.8):")
print(result)
