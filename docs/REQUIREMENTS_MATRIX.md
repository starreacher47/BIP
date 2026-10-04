# Матрица выполнения требований

| Требование | Реализация |
|---|---|
| GUI аутентификации | `/login`, `/register`, адаптивные шаблоны |
| 2FA login/password + OTP | TOTP `pyotp`, `/login/otp` |
| Внешний OAuth | GitHub через Authlib |
| Локальный OAuth | Keycloak в Docker Compose |
| Роли | user/admin/superuser |
| Смена пароля/аватара | `/profile/security`, `/profile/avatar` |
| Деактивация сессий | пользователь и superuser |
| API tokens | хешированные API keys, управление в admin |
| 413/415 | централизованные handlers |
| Файлы до 2 ГБ | chunk API, `MAX_CONTENT_LENGTH`, потоковая запись |
| WebSocket progress | Flask-SocketIO room по upload ID |
| S3 | MinIO client и bucket |
| Share direct URL | случайный хешируемый токен, TTL, ACL |
| Admin/User GUI | Bootstrap-free responsive UI |
| REST API | `/api/v1` |
| Mobile | viewport, responsive grid, touch targets >=44px |
| SOP/CSP/CORS | middleware headers и allowlist/403 |
| CSRF | Flask-WTF во всех HTML POST формах |
| API auth | X-API-Key/Bearer, 401 |
| Rate limit | 10/min per route/IP, 429 |
| UUIDv7 logging | request_logs + X-Request-Id |
| Hardening | non-root/read-only/cap_drop/no-new-privileges, docs |
| Nginx TLS/HSTS | reverse proxy config + Certbot procedure |
| Prometheus/Grafana | app metrics, node exporter, dashboard |
| SemVer | VERSION, CHANGELOG, tag workflows |
| CI variables | documented secrets and variables |
| SonarQube | GitHub/GitLab pipeline |
| Trivy | container scan pipeline |
| CI release | ZIP release and registry image |
