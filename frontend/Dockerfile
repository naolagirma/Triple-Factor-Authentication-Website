FROM php:8.1-fpm-alpine

# install nginx and curl for the attack proxy
RUN apk add --no-cache nginx curl-dev \
    && docker-php-ext-install curl

# nginx config
COPY nginx.conf /etc/nginx/http.d/default.conf

# application files
COPY index.php      /var/www/html/
COPY attack_proxy.php /var/www/html/
COPY generate_token.php /var/www/html/
COPY css/           /var/www/html/css/
COPY js/            /var/www/html/js/

# make sure nginx can write its pid and logs
RUN mkdir -p /run/nginx \
    && chown -R www-data:www-data /var/www/html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]
