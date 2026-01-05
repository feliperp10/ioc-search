import ipaddress #Verify IPs
import re #Verify all the rest

def identify_ioc_type(ioc: str) -> str:
    # 1. Verificar se é IP
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # 2. Verificar se é um Hash MD5 (32 caracteres hex)
    if re.fullmatch(r"([a-fA-F0-9]{32})", ioc):
        return "md5"
    
    # 3. Verificar se é um Hash SHA-256 (64 caracteres hex)
    if re.fullmatch(r"([a-fA-F0-9]{64})", ioc):
        return "sha256"

    # 4. Verificar se parece um domínio (simples)
    if re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", ioc.lower()):
        return "domain"

    return "unknown"

# Teste simples
if __name__ == "__main__":
    test_ioc = "8.8.8.8"
    print(f"O IOC {test_ioc} é do tipo: {identify_ioc_type(test_ioc)}")