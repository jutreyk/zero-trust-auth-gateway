# zero-trust-auth-gateway

Сервис аутентификации и авторизации на Go с архитектурой Zero-Trust.

## Возможности
- Двухфакторная аутентификация (2FA) по стандарту RFC 6238 TOTP (Google Authenticator).
- Ротация refresh-токенов с обнаружением повторного использования скомпрометированных токенов (Token Family Reuse Detection).
- Rate Limiting на скользящем окне для защиты от перебора паролей.
- Разграничение прав доступа на основе ролей (RBAC).
- Аудит событий безопасности.

## Эндпоинты

- `POST /api/v1/auth/register` — регистрация
- `POST /api/v1/auth/login` — вход (пароль + 2FA код)
- `POST /api/v1/auth/refresh` — ротация токенов
- `POST /api/v1/auth/2fa/setup` — генерация секрета TOTP
- `POST /api/v1/auth/2fa/verify` — подтверждение и включение 2FA
- `GET /api/v1/secure/resource` — защищенный эндпоинт
- `GET /api/v1/admin/audit-logs` — журнал аудита

## Запуск

```bash
go run main.go
```
