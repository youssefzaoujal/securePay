FROM node:22-alpine AS runtime
WORKDIR /app
COPY package.json index.js ./
RUN addgroup -S securepay && adduser -S -G securepay securepay \
  && chown -R securepay:securepay /app
USER securepay
EXPOSE 8015
ENV PORT=8015
CMD ["node", "index.js"]
