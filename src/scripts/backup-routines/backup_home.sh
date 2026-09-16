#!/bin/bash
# ==============================================================================
# Script de Backup Seguro para Cronicle
# ==============================================================================
# Melhorias implementadas:
# - Strict mode (set -euo pipefail) para falhar imediatamente em caso de erro.
# - Suporte a variáveis de ambiente (injetadas pelo Cronicle) com fallbacks.
# - Limpeza automática de backups antigos (Retenção).
# - Validação de dependências (tar, openssl).
# - O Cronicle captura a saída padrão, então o uso do 'echo' já serve como log no painel.

set -euo pipefail

# ==========================================
# Configurações (Podem ser sobrescritas no painel do Cronicle via Variáveis)
# ==========================================
SOURCE_DIR="${CRONICLE_SOURCE_DIR:-/home}"
DEST_DIR="${CRONICLE_DEST_DIR:-/opt/backups_home}"
RETENTION_DAYS="${CRONICLE_RETENTION_DAYS:-7}"
LOG_FILE="${CRONICLE_LOG_FILE:-/var/log/backup_home.log}"
KEY_FILE="${CRONICLE_KEY_FILE:-/root/.backup_key}"

DATE=$(date +"%Y%m%d_%H%M%S")
ENCRYPTED_FILE="${DEST_DIR}/backup_home_${DATE}.tar.gz.enc"

# Função para logging duplo (Cronicle stdout + arquivo local)
log() {
    local message="[$(date +"%Y-%m-%d %H:%M:%S")] $1"
    echo "$message"
    echo "$message" >> "$LOG_FILE"
}

# ==========================================
# Pré-requisitos
# ==========================================
log "Iniciando rotina de backup do diretório: $SOURCE_DIR..."

# Verifica se os comandos necessários existem
for cmd in tar openssl find; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "ERRO: Dependência '$cmd' não encontrada no sistema."
        exit 1
    fi
done

# Verificação do arquivo de chave
if [ ! -f "$KEY_FILE" ]; then
    log "ERRO: Arquivo de chave $KEY_FILE não encontrado."
    log "Por favor, crie o arquivo com a senha antes de executar o script."
    exit 1
fi

# Valida se o diretório de origem existe
if [ ! -d "$SOURCE_DIR" ]; then
    log "ERRO: Diretório de origem '$SOURCE_DIR' não existe."
    exit 1
fi

# Criação do diretório de destino se não existir
if [ ! -d "$DEST_DIR" ]; then
    log "Diretório $DEST_DIR não encontrado. Criando com permissões restritas..."
    mkdir -p "$DEST_DIR"
    chmod 700 "$DEST_DIR"
fi

# ==========================================
# Execução do Backup
# ==========================================
log "Iniciando compactação e criptografia AES-256-CBC em tempo real..."

# O 'set -o pipefail' garante que se o 'tar' falhar, o script aborte,
# mesmo que o 'openssl' retorne 0.
if tar -czf - "$SOURCE_DIR" 2>/dev/null | openssl enc -aes-256-cbc -salt -pbkdf2 -md sha256 -iter 100000 -pass file:"$KEY_FILE" -out "$ENCRYPTED_FILE"
then
    FILE_SIZE=$(du -h "$ENCRYPTED_FILE" | cut -f1)
    log "Sucesso! Backup criado e criptografado: $ENCRYPTED_FILE (Tamanho: $FILE_SIZE)"
else
    log "ERRO CRÍTICO: Falha durante a compactação ou criptografia."
    # Remove arquivo corrompido ou incompleto
    rm -f "$ENCRYPTED_FILE"
    exit 1
fi

# ==========================================
# Limpeza de Backups Antigos (Retenção)
# ==========================================
log "Verificando backups mais antigos que $RETENTION_DAYS dias em $DEST_DIR..."
# Procura arquivos com extensão .enc e remove os antigos
DELETED_FILES=$(find "$DEST_DIR" -type f -name "backup_home_*.tar.gz.enc" -mtime +$RETENTION_DAYS -print -delete)

if [ -n "$DELETED_FILES" ]
then
    log "Os seguintes backups antigos foram removidos pela política de retenção:"
    echo "$DELETED_FILES" | while read -r line; do log " -> Removido: $line"; done
else
    log "Nenhum backup antigo precisou ser removido hoje."
fi

log "Rotina de backup finalizada com sucesso."
exit 0
