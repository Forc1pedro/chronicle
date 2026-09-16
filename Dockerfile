FROM ubuntu:24.04

# Atualizar pacotes base e instalar dependências necessárias
RUN apt-get update && \
    apt-get install -y curl build-essential ca-certificates dos2unix && \
    rm -rf /var/lib/apt/lists/*

# Instalar Node.js v22 (v22.12+)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Definir o diretório de trabalho do Cronicle
WORKDIR /opt/cronicle

# Copiar os arquivos do projeto para o container
COPY . /opt/cronicle/

# Executar a instalação e o build conforme você solicitou
RUN node bin/install.js && \
    npm install && \
    node bin/build.js dist

# Dar permissão de execução ao script de entrypoint
COPY docker-entrypoint.sh /opt/cronicle/
RUN find /opt/cronicle/bin -type f \( -name "*.sh" -o -name "*.js" \) -exec dos2unix {} + && \
    dos2unix /opt/cronicle/docker-entrypoint.sh && \
    chmod +x /opt/cronicle/docker-entrypoint.sh

# Expor a porta padrão do Cronicle
EXPOSE 3012

# Iniciar via entrypoint script
ENTRYPOINT ["/opt/cronicle/docker-entrypoint.sh"]
