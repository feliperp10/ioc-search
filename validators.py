import ipaddress
import re

def identify_ioc_type(ioc):
    ioc = ioc.strip()
    
    # 1. Validação de IP (v4 e v6) usando biblioteca nativa
    try:
        ip = ipaddress.ip_address(ioc)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"
        if isinstance(ip, ipaddress.IPv6Address):
            return "ipv6"
    except ValueError:
        pass

    # 2. Validação de Hashes (Regex)
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"

    # 3. Validação de URL/Domínio simples
    if "." in ioc:
        return "url"

    return "unknown"