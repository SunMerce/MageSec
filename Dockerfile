FROM php:8.3-cli-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends $PHPIZE_DEPS ca-certificates curl git libyaml-dev unzip \
 && pecl install yaml \
 && docker-php-ext-enable yaml \
 && apt-get purge -y --auto-remove $PHPIZE_DEPS \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

ENV GITHUB_ACTION_PATH=/app

WORKDIR /app
COPY . /app

ENTRYPOINT ["php", "/app/entrypoint.php"]