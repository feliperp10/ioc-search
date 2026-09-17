#!/bin/bash
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Detecta automaticamente o diretório onde este script está localizado
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="/usr/local/bin/ioc-search"

echo -e "${BLUE}[*] Projeto detectado em: ${PROJECT_DIR}${NC}"

if [ ! -f "$PROJECT_DIR/.venv/bin/python" ]; then
    echo -e "${BLUE}[*] Ambiente virtual (.venv) não encontrado. Criando...${NC}"
    python3 -m venv "$PROJECT_DIR/.venv"
    "$PROJECT_DIR/.venv/bin/pip" install --upgrade pip >/dev/null
    "$PROJECT_DIR/.venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
fi

echo -e "${BLUE}[*] Corrigindo permissões e wrapper global...${NC}"
chmod +x "$PROJECT_DIR/cli.py"

# Cria wrapper global usando o caminho detectado dinamicamente
sudo bash -c "cat << EOF > $BIN_PATH
#!/bin/bash
${PROJECT_DIR}/.venv/bin/python ${PROJECT_DIR}/cli.py \"\\\$@\"
EOF"

sudo chmod +x "$BIN_PATH"

echo -e "${GREEN}[V] Concluído! Teste agora com: ioc-search history${NC}"
