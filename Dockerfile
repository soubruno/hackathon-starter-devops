FROM node:18-alpine

WORKDIR /app

# Copia dependências
COPY package*.json ./

# Instala apenas dependências de produção para manter a imagem leve
RUN npm ci --omit=dev

# Copia o restante do código da aplicação
COPY . .

# Variável de ambiente padrão
ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["npm", "start"]