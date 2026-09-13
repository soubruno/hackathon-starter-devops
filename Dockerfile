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

# Expõe a porta padrão da aplicação
EXPOSE 8080

# Inicia a aplicação
CMD ["node", "app.js"]