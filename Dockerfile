# Используем официальный образ Node.js 22 на Alpine
FROM node:22-alpine

ARG USER_ID=1000
ARG GROUP_ID=1000

# Если UID и GID стандартные (1000) — используем пользователя node из образа,
# иначе удаляем node и создаём своего пользователя и группу
RUN if [ "$USER_ID" = "1000" ] && [ "$GROUP_ID" = "1000" ]; then \
      echo "Using default node user"; \
    else \
      deluser node && \
      delgroup node && \
      addgroup -g $GROUP_ID appgroup && \
      adduser -S -u $USER_ID -G appgroup appuser; \
    fi

# Рабочий каталог
WORKDIR /app

# Копируем package.json с нужным владельцем
RUN if [ "$USER_ID" = "1000" ] && [ "$GROUP_ID" = "1000" ]; then \
      chown node:node /app || true; \
    else \
      chown $USER_ID:$GROUP_ID /app || true; \
    fi

COPY package*.json ./

# Устанавливаем зависимости под нужным пользователем
RUN if [ "$USER_ID" = "1000" ] && [ "$GROUP_ID" = "1000" ]; then \
      npm ci && npm cache clean --force; \
    else \
      su-exec $USER_ID:$GROUP_ID npm ci && npm cache clean --force; \
    fi

# Копируем исходники с нужным владельцем
COPY . .

# Генерируем Prisma клиента
RUN if [ "$USER_ID" = "1000" ] && [ "$GROUP_ID" = "1000" ]; then \
      npx prisma generate; \
    else \
      su-exec $USER_ID:$GROUP_ID npx prisma generate; \
    fi

# Переключаемся на пользователя (либо node, либо созданный)
USER ${USER_ID}

EXPOSE 10005

CMD ["npm", "run", "start:dev"]
