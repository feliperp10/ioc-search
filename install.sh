#!/bin/bash
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="/home/felipe/ioc-search"
BIN_PATH="/usr/local/bin/ioc-search"

echo -e "${BLUE}[*] Corrigindo permissões e wrapper global...${NC}"

# Garantir executável
chmod +x "$PROJECT_DIR/cli.py"

# Criar wrapper robusto usando aspas simples para o EOF para evitar expansão de variáveis indesejadas
sudo bash -c "cat << 'EOF' > $BIN_PATH
#!/bin/bash
# Executa a venv do projeto com os argumentos passados
/home/felipe/ioc-search/.venv/bin/python /home/felipe/ioc-search/cli.py \"\$@\"
EOF"

sudo chmod +x $BIN_PATH

echo -e "${GREEN}[V] Concluído! Teste agora com: ioc-search history${NC}"