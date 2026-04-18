FROM php:8.3-cli
RUN apt-get update -qq && apt-get install -y -qq unzip > /dev/null 2>&1
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
WORKDIR /app
COPY composer.json phpunit.xml ./
RUN composer install -q --no-security-blocking
COPY src/ src/
COPY tests/ tests/
CMD ["vendor/bin/phpunit", "--colors=always"]
