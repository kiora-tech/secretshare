# =============================================================================
# Base : PHP-FPM et les seules extensions utiles (Postgres, intl, opcache)
# =============================================================================
FROM php:8.4-fpm-alpine AS base

# Deux scripts tiers, épinglés à une version et vérifiés octet pour octet : une nouvelle
# publication de leurs auteurs ne peut pas entrer dans l'image sans changer ces lignes.
ADD --chmod=755 --checksum=sha256:9c26dd516b8147235c4e924c52e2f076fb2b3f278f5457e88918518ebfee9e01 \
    https://github.com/mlocati/docker-php-extension-installer/releases/download/2.12.3/install-php-extensions /usr/local/bin/
RUN install-php-extensions pdo_pgsql intl opcache

RUN apk add --no-cache bash fcgi
# php-fpm-healthcheck v0.6.0
ADD --chmod=755 --checksum=sha256:53bc616c4a30f029b98bff48fdeb0c4da252cb11e4f86656a8222a67dc4e5009 \
    https://raw.githubusercontent.com/renatomefi/php-fpm-healthcheck/a2d45de918787f761754b96b94a59f4f6acebc25/php-fpm-healthcheck /usr/local/bin/php-fpm-healthcheck

RUN addgroup -g 1000 -S symfony && adduser -u 1000 -S symfony -G symfony
WORKDIR /var/www/html

COPY docker/php/php.ini /usr/local/etc/php/php.ini
COPY docker/php/www.conf /usr/local/etc/php-fpm.d/www.conf

# =============================================================================
# Développement : le code est monté en volume
# =============================================================================
FROM base AS dev

RUN apk add --no-cache git
COPY --from=composer:2@sha256:b6dcd72ca98fa19d0e5b8476de179859704891fad06dd9e0b96833d4c430a5fc /usr/bin/composer /usr/bin/composer
RUN chown -R symfony:symfony /var/www/html
USER symfony
EXPOSE 9000
CMD ["php-fpm"]

# =============================================================================
# CI : le code tel quel, pour les tests de démarrage
# =============================================================================
FROM base AS ci

COPY --chown=symfony:symfony . /var/www/html
RUN mkdir -p var/cache var/log && chown -R symfony:symfony var
USER symfony
EXPOSE 9000
CMD ["php-fpm"]

# =============================================================================
# Production : dépendances et assets préparés par la CI (vendor/, public/assets/)
# =============================================================================
FROM base AS prod

COPY --chown=symfony:symfony . /var/www/html
RUN mkdir -p var/cache var/log \
    && php bin/console cache:warmup --env=prod \
    && chown -R symfony:symfony var
USER symfony
EXPOSE 9000
CMD ["php-fpm"]
