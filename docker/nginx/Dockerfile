FROM nginx:stable-alpine AS base

RUN apk add --no-cache curl \
    && rm -f /etc/nginx/conf.d/default.conf
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf

# Développement : public/ est monté en volume
FROM base AS dev

# Production : les assets compilés (public/assets/) sont servis directement
FROM base AS prod

COPY --chown=nginx:nginx public /var/www/html/public
RUN chmod -R 755 /var/www/html/public
