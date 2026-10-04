# Token & Session Security Auditor v2.0.0

Учебно-практическая система для безопасной обработки токенов и сессионных идентификаторов. Анализирует HTTP/HTTPS-трафик через mitmproxy и встроенный observer Flask, выявляет токены в cookie, Authorization, URL и теле запроса, обнаруживает hijacking/fixation, повторное использование токенов, небезопасные cookie и истёкшие JWT.

## Возможности

- регистрация с подтверждением email/телефон OTP или токеном приглашения;
- логин/пароль и TOTP 2FA;
- GitHub OAuth и локальный OIDC/OAuth-провайдер Keycloak;
- роли `user`, `admin`, `superuser`, смена пароля/аватара, отзыв сессий;
- защищённый REST API: API Key/Bearer, CORS allowlist, CSRF для форм, CSP, SOP, rate limit 10/мин;
- UUIDv7 Request ID во всех логах и заголовке `X-Request-Id`;
- загрузка файлов до 2 ГБ кусками без помещения всего файла в RAM, WebSocket-прогресс, MinIO и защищённые временные ссылки;
- SQLite, PDF-отчёты, Prometheus/Grafana, Nginx TLS/HSTS;
- Docker, GitHub Actions, SonarQube и Trivy.

## Быстрый локальный запуск

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Откройте `http://127.0.0.1:5000`. Администратор: значения `ADMIN_USERNAME` и `ADMIN_PASSWORD` из `.env`.

## Полный стенд

```bash
cp .env.example .env
docker compose up --build
```

Перед запуском замените все секреты. Для TLS создайте сертификаты Certbot и укажите реальный домен в `deploy/nginx/nginx.conf`. Keycloak доступен внутри Docker-сети; создайте realm `token-auditor`, OIDC client и внесите client secret в `.env`.

## REST API

1. Суперпользователь создаёт API key в админ-панели.
2. Передавайте `X-API-Key: tsa_...` или `Authorization: Bearer tsa_...`.
3. Все методы `/api/v1/*` ограничены 10 запросами в минуту.

Создание загрузки:

```bash
curl -X POST http://127.0.0.1:5000/api/v1/uploads \
 -H 'X-API-Key: tsa_...' -H 'Content-Type: application/json' \
 -d '{"filename":"traffic.json","size":1048576,"content_type":"application/json"}'
```

Отправка частей: `PUT /api/v1/uploads/{id}/chunks`, `Content-Type: application/octet-stream`.

## Версионирование

SemVer `vX.Y.Z`: major — несовместимые изменения API, minor — новые совместимые функции, patch — исправления. Релиз создаётся тегом, например `git tag v2.0.0 && git push origin v2.0.0`.

Подробности: `docs/SYSTEM_SPECS.md`, `docs/USER_SPECS.md`, `docs/DEPLOY.md`, `docs/SECURITY.md`, `docs/COMPARATIVE_ANALYSIS.md`.
