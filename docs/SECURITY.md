# Меры обеспечения безопасности

- SOP обеспечивается браузером и отсутствием разрешений на произвольные cross-origin операции.
- CSP: строгие `default-src`, `script-src`, `style-src`; запрещены frame ancestors и внешние base URI.
- CORS возвращается только доверенным origin; остальные origin на `/api` получают 403.
- Все HTML POST-формы содержат уникальный CSRF token; API исключён из cookie-CSRF и защищён API key/Bearer.
- Rate limit — 10 запросов/минуту на каждый защищённый метод; превышение — 429.
- Каждый запрос получает UUIDv7, журналируется и возвращается в `X-Request-Id`.
- Session cookie использует HttpOnly, SameSite=Lax и Secure при HTTPS; HSTS задаётся Nginx и приложением.
- Токены в анализе сохраняются как SHA-256 fingerprint и сокращённое preview.

## Hardening хоста
Запретите SSH root login (`PermitRootLogin no`), password login после настройки ключей, перенесите порт, включите `fail2ban`, сложные пароли и UFW только для SSH/80/443. Запускайте Docker rootless либо отдельным непривилегированным пользователем. Обновляйте ОС и контейнеры, включите auditd и резервное копирование SQLite/MinIO.

## Ограничения
Встроенное шифрование внешних токенов является учебной реализацией. Для production требуется Vault/KMS с ротацией ключей. Атаки из `analyzer/attack_simulator.py` разрешены только для localhost и явно разрешённых целей.
