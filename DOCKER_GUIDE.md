# Guia de Adaptação Docker: Chrontasks (Cronicle) - author: Joseph Huckaby || adpt: João Pedro - For1sec

Este documento detalha como construir e executar o projeto usando Docker e Docker Compose, utilizando os arquivos de configuração presentes na raiz do projeto.

## Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) instalado.
- [Docker Compose](https://docs.docker.com/compose/install/) instalado.

---

## 1. Construindo e Executando com Docker (Forma Manual)

Se você deseja construir a imagem e rodar o container manualmente apenas com a CLI do Docker, siga os passos abaixo:

### Construir a Imagem
Na raiz do projeto (onde o `Dockerfile` está localizado), execute:
```bash
docker build -t chrontasks:latest .
```
Isso utilizará o `Dockerfile` que baixa o Ubuntu 24.04, instala o Node.js v22 e executa os scripts de instalação e build do Cronicle (`node bin/install.js`, `npm install`, `node bin/build.js dist`).

### Executar o Container
Após a construção da imagem, execute o container expondo a porta `3012` e mapeando os volumes necessários para persistência de dados:
```bash
docker run -d \
  --name chrontasks \
  --hostname chrontasks \
  -p 3012:3012 \
  -v cronicle-data:/opt/cronicle/data \
  -v cronicle-logs:/opt/cronicle/logs \
  -v cronicle-conf:/opt/cronicle/conf \
  chrontasks:latest
```

---

## 2. Construindo e Executando com Docker Compose (Forma Recomendada)

O método mais fácil e organizado de orquestrar a aplicação é usar o `docker-compose.yml`. Ele já configura as portas, os volumes persistentes e o build da imagem automaticamente.

### Subir os Serviços (Build e Run)
Para construir a imagem (se necessário) e iniciar o serviço em segundo plano (modo detached), execute:
```bash
docker compose up -d --build
```

### Visualizar os Logs
Para acompanhar o que está acontecendo dentro do container (útil para debugar o script `docker-entrypoint.sh`):
```bash
docker compose logs -f
```

### Parar os Serviços
Para parar e remover os containers gerados pelo Compose (os volumes nomeados continuam intactos):
```bash
docker compose down
```

---

## Arquitetura e Volumes

O projeto utiliza **Volumes Nomeados** para garantir que os dados não sejam perdidos caso o container seja recriado ou atualizado.

- `cronicle-data`: Armazena os dados internos do banco.
- `cronicle-logs`: Persiste os logs de execução e jobs.
- `cronicle-conf`: Mantém as configurações (`config.json`, `setup.json`).
- `./htdocs`: Volume do tipo bind-mount mapeado para `/opt/cronicle/htdocs`, permitindo desenvolvimento e alteração dos arquivos do painel web em tempo real (o código que roda no navegador).

## Acessando o Painel
Com o container rodando, acesse a interface web através do seu navegador:
**http://localhost:3012**
