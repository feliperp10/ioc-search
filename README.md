# 🛡️ IOC Search Tool - Threat Intelligence CLI

A high-performance command-line interface (CLI) tool designed for security analysts to perform rapid Threat Intelligence lookups. It aggregates data from multiple providers to analyze IP addresses (IPV4 and IPV6), Domains, URLs, and File Hashes.

The IOC Search Tool is a centralized security intelligence hub designed to automate the investigation of digital threats. Instead of manually visiting multiple security websites to verify if an IP address, web link, or file is dangerous, this tool queries several global databases simultaneously in seconds.

What is the business value?

* Operational Efficiency: It reduces the time spent on initial threat analysis by up to 90%, allowing security teams to respond to incidents faster.

* Cost Optimization: By using a "Smart Cache" system, the tool avoids redundant requests, maximizing the use of free security data tiers and reducing the need for expensive premium licenses.

* Data-Driven Decisions: It provides clear, consolidated reports (Clean/Alert) that help managers make informed decisions about blocking or allowing network traffic without needing to be a technical expert.

* Standardization: It ensures that every investigation follows the same rigorous process, pulling data from world-class providers like Google and VirusTotal.

###  Features
* **Multi-Provider Analysis**: Integration with VirusTotal, AbuseIPDB, AlienVault OTX, HybridAnalysis, GreyNoise, and Google Safe Browsing.
* **Network Insights**: Automatically identifies **ASN** and **ISP/Organization** for IP addresses.
* **Intelligent Caching**: Stores results for **48 hours** in a local SQLite database.
* **Clean UI**: Professional tables and color-coded threat levels (Clean, Info, Alert).

###  Installation & System Utility Setup
To use this tool from anywhere in your terminal as `ioc-search`, follow these steps:

  1. **Clone and Install**:
```bash
git clone https://github.com/feliperp10/ioc-search.git
cd ioc-search
pip install -r requirements.txt
   ```

2. **Set up Global Alias:**

Add the tool to your shell configuration (Bash or ZSH):

```
# Open your config file
nano ~/.bashrc  # or ~/.zshrc

# Add this line at the end
alias ioc-search='python3 ~/ioc-search/cli.py'
```

3. **Reload Config:**
```
source ~/.bashrc  # or ~/.zshrc
```
4. **Usage:**

* Single Scan:
```
ioc-search scan -i 8.8.8.8
```
* File Scan: 
```
ioc-search scan -f targets.txt
```
* History: 
```
ioc-search scan history
```
* Export options:
```
ioc-search scan -i 8.8.8.8 -e json
```
```
ioc-search scan -i 8.8.8.8 -e csv
```

---
**🇧🇷 Versão em Português**

# 🛡️ IOC Search Tool - Threat Intelligence CLI

Uma ferramenta de linha de comando (CLI) de alta performance, desenvolvida para analistas de segurança realizarem consultas rápidas de Threat Intelligence. Ela agrega dados de múltiplos provedores para analisar endereços IP (IPv4 e IPv6), domínios, URLs e hashes de arquivos.

A IOC Search Tool é uma central de inteligência de segurança projetada para automatizar a investigação de ameaças digitais. Em vez de um analista visitar manualmente vários sites de segurança para verificar se um IP, link ou arquivo é perigoso, esta ferramenta consulta diversos bancos de dados globais simultaneamente em poucos segundos.

Qual o ganho de valor no seu uso?
* Eficiência Operacional: Reduz o tempo gasto na análise inicial de ameaças em até 90%, permitindo que a equipe de segurança responda a incidentes com muito mais agilidade.

* Otimização de Custos: Através de um sistema de "Cache Inteligente", a ferramenta evita consultas redundantes, maximizando o uso de créditos gratuitos de dados e reduzindo a necessidade imediata de licenças premium caras.

* Decisões Baseadas em Dados: Oferece relatórios consolidados e claros (Limpo/Alerta) que ajudam gestores a tomar decisões informadas sobre bloquear ou permitir tráfego na rede, sem a necessidade de ser um especialista técnico.

* Padronização: Garante que toda investigação siga o mesmo processo rigoroso, extraindo dados de provedores de classe mundial como Google e VirusTotal.

Funcionalidades:

* Análise Multi-Provedor: Integração com VirusTotal, AbuseIPDB, AlienVault OTX, HybridAnalysis, GreyNoise e Google Safe Browsing.

* Insights de Rede: Identifica automaticamente ASN e ISP/Organização associados a endereços IP.

* Cache Inteligente: Armazena resultados por 48 horas em um banco SQLite local.

* Interface Limpa: Tabelas profissionais e níveis de ameaça com cores (Clean, Info, Alert).

Instalação & Configuração como Utilitário do Sistema

Para utilizar a ferramenta de qualquer lugar do terminal com o comando ioc-search, siga os passos abaixo:

1. **Clonar e instalar:**

```bash
git clone https://github.com/feliperp10/ioc-search.git
cd ioc-search
pip install -r requirements.txt
   ```

2. **Configurar Alias Global:**

Adicione a ferramenta à configuração do seu shell (Bash ou ZSH):

```
# Abra seu arquivo de configuração
nano ~/.bashrc  # or ~/.zshrc

# Adicione esta linha no final
alias ioc-search='python3 ~/ioc-search/cli.py'
```

3. Recarregar a configuração
```
source ~/.bashrc  # ou ~/.zshrc
```
4. **Como usar:**

* Scan único:
```
ioc-search scan -i 8.8.8.8
```
* Scan via arquivo:
  
```
ioc-search scan -f targets.txt
```
* Histórico:
```
ioc-search scan history
```
* Opções de exportação
```
ioc-search scan -i 8.8.8.8 -e json
```
```
ioc-search scan -i 8.8.8.8 -e csv
```
