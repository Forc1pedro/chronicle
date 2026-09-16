#!/bin/bash
set -e

# Garante que o diretório conf exista e tenha o arquivo de configuração base
if [ ! -f "/opt/cronicle/conf/config.json" ]; then
    echo "Copiando arquivos de configuração padrão..."
    mkdir -p /opt/cronicle/conf
    cp -a /opt/cronicle/sample_conf/. /opt/cronicle/conf/
fi

# Se a pasta data estiver vazia (primeira execução), rodamos o setup
if [ ! -d "/opt/cronicle/data" ] || [ -z "$(ls -A /opt/cronicle/data 2>/dev/null)" ]; then
    echo "Inicializando o storage do Cronicle (setup)..."
    /opt/cronicle/bin/control.sh setup
fi

echo "Iniciando o servidor Cronicle..."
mkdir -p /opt/cronicle/logs
touch /opt/cronicle/logs/Cronicle.log

# Iniciar o Cronicle via control.sh start
/opt/cronicle/bin/control.sh start

# Para manter o contêiner rodando, damos um tail no log principal do Cronicle
echo "Cronicle iniciado. Lendo logs..."
tail -f /opt/cronicle/logs/Cronicle.log
