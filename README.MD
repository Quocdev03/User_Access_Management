# UAM — User Access Management

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## Giới thiệu dự án

UAM là backend quản lý tài khoản, xác thực và phân quyền. Dự án được tổ chức theo
domain-first modular monolith, giữ HTTP contract ổn định trong khi tách rõ domain,
HTTP adapter và hạ tầng lưu trữ.

Các tài liệu kiến trúc, domain, dữ liệu, use case và vận hành nằm tại
[docs/README.md](./docs/README.md). OpenAPI được sinh tại `docs/openapi/`; không sửa
trực tiếp các file generated.

## Công nghệ

- Go 1.26 và Gin
- MySQL cho account, session, RBAC, workflow và outbox
- Redis cho rate limit, ban, JTI revoke, MFA và worker lease
- JWT, TOTP MFA, bcrypt và email worker qua SMTP
- Docker Compose và Mailpit cho môi trường local

## Setup cơ bản

Yêu cầu: Go 1.26+, Docker Desktop và Docker Compose.

```powershell
# Khởi động MySQL, Redis và Mailpit.
docker compose up -d

# Tạo cấu hình local.
Copy-Item .env.example .env

# Chạy migration một lần, rồi chạy worker và API ở hai terminal riêng.
go run ./cmd/migrate
go run ./cmd/worker
go run ./cmd/server
```

Sau khi chạy, API ở `http://localhost:8080`, health check ở
`http://localhost:8080/health`, Mailpit ở `http://localhost:8025` và Swagger ở
`http://localhost:8080/swagger/index.html` khi `APP_ENV=development`.
