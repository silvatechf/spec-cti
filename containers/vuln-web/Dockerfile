# Usa uma versão desatualizada e sem patches de segurança recentes
FROM php:7.4-apache

# Instala o driver do SQLite
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev \
    && docker-php-ext-install pdo pdo_sqlite \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copia a aplicação vulnerável
COPY index.php /var/www/html/index.php

# Ajusta permissões seguindo o privilégio mínimo (O Apache precisa escrever no /tmp para o SQLite)
RUN chown -R www-data:www-data /var/www/html \
    && chown www-data:www-data /tmp

# Expõe a porta 80 apenas para a rede Docker interna (conforme o docker-compose.yml)
EXPOSE 80