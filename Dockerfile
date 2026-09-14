# Usa versão moderna do Node.js sobre Alpine Linux
FROM node:22-alpine

# Define o diretório de trabalho no container
WORKDIR /app

# Copia manifestos de dependências
COPY package*.json ./

# Instala dependências de produção sem disparar scripts adicionais
RUN npm install --omit=dev --ignore-scripts --no-audit

# Copia os arquivos da aplicação
COPY . .

# Cria o diretório de estilos e gera os assets caso o script exista
RUN mkdir -p public/css && npm run build --if-present

# Expõe a porta padrão da aplicação
EXPOSE 8080

# Inicia a aplicação
CMD ["node", "app.js"]