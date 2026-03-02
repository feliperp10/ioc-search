IOC Search Tool 🛡️

IOC Search Tool é um agregador de Threat Intelligence desenvolvido em Python para analistas de SOC e Incident Response. A ferramenta automatiza a consulta de múltiplos provedores, consolidando reputação, vereditos de sandbox e enriquecimento de infraestrutura numa única interface de linha de comando (CLI).O diferencial desta versão é a capacidade de processar respostas complexas de sandbox, filtrando relatórios de execução com erro e extraindo vereditos precisos de ambientes de sucesso.

🚀 Funcionalidades
Busca Multi-Entidade: Suporte para IPv4, IPV6, URLs, Domínios e Hashes (MD5, SHA1, SHA256).

Análise Avançada de Hashes: Integração com Hybrid Analysis (Falcon Sandbox) para obter vereditos de detonação real.

Enriquecimento de Rede: Extração automática de ASN, Proprietário (Owner) e ISP via VirusTotal e AbuseIPDB.

Inteligência GreyNoise: Identificação de scanners comuns e IPs pertencentes ao RIOT (serviços legítimos conhecidos).

Interface Visual: Tabelas formatadas com cores semânticas (Vermelho para Malicioso, Amarelo para Suspeito, Verde para Limpo).

Exportação de Dados: Suporte para gerar relatórios em JSON e CSV com timestamps automáticos.

📥 Instalação e Setup

Clonar o repositório:

git clone https://github.com/feliperp10/ioc-search.git
cd ioc-search

Configurar o ambiente virtual:
python3 -m venv .venv
source .venv/bin/activate  # No Windows use: .venv\Scripts\activate

Instalar dependências:
pip install typer rich requests python-dotenv

Configurar chaves de API:Crie um arquivo .env na raiz do projeto (use o .env.example como base):

VT_API_KEY=sua_chave_aqui
HYBRID_API_KEY=sua_chave_aqui
OTX_API_KEY=sua_chave_aqui
ABUSE_API_KEY=sua_chave_aqui
GREYNOISE_API_KEY=sua_chave_aqui
GOOGLE_API_KEY=sua_chave_aqui

💻 Exemplos de UsoInvestigar um Indicador Único:
python3 cli.py -i 1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820

Analisar Lista a partir de Arquivo
python3 cli.py -f lista_iocs.txt

Exportar para CSV:
python3 cli.py -i <IOC> -e csv

Exportar para JSON:
python3 cli.py -i <IOC> -e json

🔍 Provedores Integrados:

Provedor,Tipo de IOC,Informação Extraída
Hybrid Analysis,Hashes,Veredito de Sandbox (ex: malicious)
VirusTotal,Global,"Motores de AV, Reputação, ASN e Owner"
AlienVault OTX,Global,Presença em Pulses de ameaças conhecidas
AbuseIPDB,IPs,Score de confiança de abuso e ISP
GreyNoise,IPs,Classificação de ruído de internet e RIOT
Safe Browsing,URLs,Classificação de risco do Google