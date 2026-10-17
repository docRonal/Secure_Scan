# Stage 1 — сборка статики
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# ⚠️ Vite "запекает" переменные окружения в статику НА ЭТАПЕ СБОРКИ.
# Браузер выполняется на хост-машине, а не внутри docker-сети — поэтому
# тут должен быть адрес, доступный именно браузеру (обычно localhost с
# опубликованным портом backend'а), а не имя docker-сервиса вроде
# "http://backend:8000" (это сработало бы только для запросов ИЗНУТРИ
# docker-сети, но не из браузера пользователя).
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
ARG VITE_AUTH_REQUIRED=true
ENV VITE_AUTH_REQUIRED=$VITE_AUTH_REQUIRED
ARG VITE_PUBLIC_REGISTRATION_ENABLED=false
ENV VITE_PUBLIC_REGISTRATION_ENABLED=$VITE_PUBLIC_REGISTRATION_ENABLED
RUN npm run build

# Stage 2 — раздача статики через nginx
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
