# Развёртывание

## Docker
Заполните `.env`, затем выполните `docker compose up -d --build`. Контейнер приложения запускается не от root, с `read_only`, `no-new-privileges` и без Linux capabilities.

## Nginx и TLS
Укажите домен, получите сертификат `certbot certonly --webroot -w deploy/certbot/www -d example.com`, перезапустите Nginx. HTTP перенаправляется на HTTPS, HSTS включён.

## Keycloak
Создайте realm `token-auditor`; client `token-auditor`, тип confidential; redirect URI `https://DOMAIN/oauth/keycloak/callback`; client secret поместите в CI/CD secret и `.env` сервера.

## MinIO
Смените root credentials, создайте bucket или разрешите приложению создать его. Установите `ENABLE_MINIO=true`.

## Мониторинг
Grafana получает Prometheus datasource автоматически. Dashboard содержит CPU, RAM, HTTP requests по классам ответов и rate-limit 429.

## CI/CD secrets
`SONAR_TOKEN`, `SONAR_HOST_URL`, registry credentials, production SSH key and `.env` values хранятся только в GitHub/GitLab Variables. Никогда не добавляйте `.env` в Git.
