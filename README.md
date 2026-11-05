# zero-trust-auth-gateway

High-assurance authentication and authorization gateway written in **Go 1.23+**. Engineered around Zero-Trust principles, incorporating RFC 6238 TOTP (Google Authenticator) 2FA, RFC 6749 Token Rotation with automatic Token Family Reuse Detection, sliding-window rate limiting, and RBAC middleware.

## Security Architecture

```
Client ──[ HTTPS / Bearer ]──▶ [ RateLimiter (Sliding Window) ]
                                      │
                                      ▼
                               [ RBAC & JWT Guard ]
                                      │
                        ┌─────────────┴─────────────┐
                        ▼                           ▼
            [ RFC 6238 TOTP Validator ]   [ Token Family Rotation ]
                                                    │
                                      (Compromised Token Replay?)
                                                    │
                                         YES ──▶ Invalidate Family
                                         NO  ──▶ Issue New Keypair
```

- **Two-Factor Authentication (2FA)**: RFC 6238 compliant Time-Based One-Time Passwords (TOTP) compatible with Google Authenticator, 1Password, and Apple Keychain.
- **Refresh Token Rotation & Theft Detection**: Every refresh generates a new token pair while revoking the former. Replay attacks using stolen tokens trigger immediate revocation of the entire token family.
- **Zero-Trust Middleware**: Enforces cryptographic signature verification, role-based access restrictions (Admin, Engineer, Viewer), and IP sliding-window rate limiting.
- **Audit Logging**: Structured security event trails recording authentication lifecycle events and blocked intrusion attempts.

## Endpoints

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Public | Create account with role |
| `POST` | `/api/v1/auth/login` | Public | Password + TOTP exchange for JWT pair |
| `POST` | `/api/v1/auth/refresh` | Public | Rotate refresh token for new credentials |
| `POST` | `/api/v1/auth/2fa/setup` | User | Provision TOTP secret & QR URI |
| `POST` | `/api/v1/auth/2fa/verify` | User | Confirm first code & enable 2FA |
| `GET` | `/api/v1/secure/resource` | Engineer/Admin | Protected zero-trust enclave |
| `GET` | `/api/v1/admin/audit-logs` | Admin | Review security event audit stream |

## Build & Test

```bash
# Run unit & security replay attack tests
go test -v ./internal/auth

# Build binary
go build -o bin/server ./cmd/server

# Run server
./bin/server
```

## License

MIT © [Arkadiy Gazizov](https://arkadiygazizov.ru)
