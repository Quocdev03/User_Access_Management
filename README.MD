# UAM — User Access Management

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Redis](https://img.shields.io/badge/Redis-7.0-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Contract Tests](https://img.shields.io/badge/Contract_Tests-41%2F41_PASS-success)](#kiểm-thử)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?logo=github-actions&logoColor=white)](.github/workflows/)
[![Dependabot](https://img.shields.io/badge/Dependabot-Active-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Backend quản lý tài khoản, xác thực phiên và phân quyền (RBAC) viết bằng Go 1.26 theo cấu trúc **Domain-First Modular Monolith**. Dự án quản lý 41 public API endpoints, 16 bảng MySQL, 34 database migrations, và chạy kèm tiến trình background worker xử lý outbox email.

---

## Kiến trúc & Luồng dữ liệu

Mã nguồn được tổ chức theo luồng phụ thuộc một chiều, tách rõ boundary giữa HTTP, Domain và Storage:

$$\text{HTTP API (internal/httpapi)} \longrightarrow \text{Domain Use Cases (internal/...)} \longrightarrow \text{Storage Adapters (internal/mysqlstore, redisstore)}$$

- **HTTP Transport (`internal/httpapi`)**: Router Gin nhận request, chạy chuỗi middleware, bind DTO (`*_contract.go`), và gọi sang use case. Không chứa logic đổi trạng thái hay query DB trực tiếp.
- **Thứ tự Middleware chống DoS**:
  1. Parse & validate body size (`ValidateJSON`)
  2. Rate limit qua Redis Token Bucket (`RateLimitMiddleware`)
  3. Xác thực JWT & phân quyền RBAC (`AuthMiddleware`, `RequirePermission`)
  4. Đọc database / Khóa dòng (`FOR UPDATE`)
  5. Xử lý mã hóa / hash (Bcrypt, HMAC, AES-GCM)
  6. Ghi database & commit transaction
- **Transaction (`pkg/database/tx.go`)**: Các thao tác ghi nhiều bảng chạy qua `TxManager.RunInTx(ctx, func(txCtx) error)`. Mọi store adapter nhận `txCtx` để dùng chung 1 transaction MySQL. Tuyệt đối không gọi Redis, gửi mail hay gọi API bên ngoài bên trong transaction MySQL.
- **Transactional Outbox (`outbox_events`)**: Khi cần gửi email OTP hoặc thông báo, use case ghi bản ghi event vào bảng `outbox_events` trong cùng transaction nghiệp vụ. Background worker (`cmd/worker`) định kỳ quét bảng này với distributed lease lock trên Redis để gửi mail qua SMTP/Mailpit.
- **Fail-Closed**: Khi Redis hoặc MySQL ngắt kết nối, middleware auth và rate limit lập tức trả lỗi HTTP 503 Service Unavailable, ngăn chặn request lọt vào tầng trong.

---

## Các Module Nghiệp vụ (`internal/`)

- **`internal/auth`**: 
  - Đăng ký tài khoản, gửi OTP kích hoạt (băm HMAC-SHA256 kèm pepper chống replay).
  - Đăng nhập xác thực mật khẩu qua Bcrypt (work factor cost 12).
  - Quên mật khẩu, đổi mật khẩu, đổi mật khẩu bắt buộc (`force-change`).
  - Xác thực hai yếu tố (MFA TOTP RFC 6238): Secret key được mã hóa bằng **AES-GCM-256** trước khi lưu vào MySQL (`mfa_secrets`); danh sách recovery codes được băm một chiều.
- **`internal/session`**:
  - Cấp phát JWT (HS256) ngắn hạn và Refresh Token dài hạn.
  - Refresh Token Rotation (RTR): Đổi refresh token cũ lấy cặp token mới; lưu lịch sử vào `refresh_token_history`.
  - Phát hiện tái sử dụng Refresh Token (Reuse Detection): Nếu một refresh token cũ đã dùng được gửi lại, hệ thống thu hồi toàn bộ phiên của người dùng đó (Token Family Revocation).
  - Thu hồi tức thì (Instant Revocation): Tăng trường `auth_version` trên MySQL khi đổi mật khẩu/đổi role để vô hiệu hóa toàn bộ access token còn hạn; ghi blacklist JTI vào Redis với TTL tương ứng.
- **`internal/access`**:
  - Quản trị RBAC: CRUD Roles, gán danh mục Permissions cho Role, gán Role cho User.
  - Bảo vệ Super Admin cuối cùng (`last_admin.go`): Khóa bi quan kiểm tra không cho phép tự hạ quyền hoặc xóa tài khoản Super Admin duy nhất còn lại trong hệ thống.
  - Quản lý danh sách người dùng (`admin/users`), đổi trạng thái tài khoản, reset mật khẩu bởi admin.
  - Xuất nhật ký kiểm toán (`admin/audit-logs/export`) theo định dạng JSON hoặc CSV.
- **`internal/account`**:
  - Lấy thông tin cá nhân (`/users/me`), cập nhật họ tên, số điện thoại, ngày sinh.
  - Quy trình đổi email an toàn: Gửi OTP xác nhận tới email mới trước khi cập nhật.
  - Xử lý ảnh đại diện (Avatar): Upload file ảnh (giới hạn dung lượng, kiểm tra mime-type), lưu trữ qua Local Storage hoặc Amazon S3/MinIO.
- **`internal/accountstate`**:
  - Máy trạng thái tài khoản tập trung: `pending` $\to$ `active` $\to$ `suspended` $\to$ `locked`.
  - Quản lý số lần nhập sai mật khẩu liên tiếp và tự động khóa tạm thời (`lockout`).
- **`internal/jobs`**:
  - `OutboxWorker`: Quét và gửi email từ `outbox_events` với retry exponential backoff.
  - `CleanupWorker`: Chạy định kỳ xóa soft-deleted records, sessions hết hạn, và xóa batch bản ghi cũ trong `refresh_token_history`.
  - `AvatarMigrationWorker`: Hỗ trợ batch migration dữ liệu avatar từ filesystem cục bộ lên S3.

---

## Cơ sở Dữ liệu & Storage

### MySQL 8.0 (16 Bảng qua 34 Migrations)
1. `schema_migrations`: Quản lý version migration (`000001` đến `000034`).
2. `users`: Thông tin tài khoản, mật khẩu băm bcrypt, trạng thái, `auth_version`.
3. `user_profiles`: Họ tên, số điện thoại, ngày sinh, avatar URL.
4. `roles`: Danh mục vai trò (`super_admin`, `admin`, `user`).
5. `permissions`: Danh mục quyền chi tiết (dạng `module:action`).
6. `role_permissions`: Quan hệ nhiều-nhiều giữa Role và Permission.
7. `user_roles`: Quan hệ nhiều-nhiều gán Role cho User.
8. `sessions`: Quản lý phiên người dùng, hash refresh token, thời điểm hết hạn.
9. `refresh_token_history`: Lịch sử xoay vòng refresh token phục vụ phát hiện reuse.
10. `user_devices`: Thông tin thiết bị, IP, User-Agent của phiên đăng nhập.
11. `audit_logs`: Nhật ký kiểm toán mọi thay đổi tài khoản và phân quyền.
12. `outbox_events`: Hàng đợi gửi email bất đồng bộ theo Transactional Outbox pattern.
13. `mfa_secrets`: Khóa bí mật TOTP mã hóa AES-GCM và phiên bản key.
14. `mfa_recovery_codes`: Danh sách mã khôi phục dự phòng đã băm.
15. `password_reset_tokens`: Token đặt lại mật khẩu sử dụng 1 lần.
16. `email_change_requests`: Phiên xác thực yêu cầu đổi địa chỉ email.

### Redis 7.0
- **Rate Limiting**: Lưu trữ bucket đếm số request theo IP và theo User ID.
- **Token Blacklist**: Lưu danh sách JTI của Access Token đã bị thu hồi đơn lẻ đến khi hết hạn TTL.
- **MFA Challenges**: Lưu tạm challenge token khi đăng nhập bước 2 có thời hạn 5 phút.
- **Worker Leases**: Khóa phân tán có thời hạn (TTL) đảm bảo chỉ 1 tiến trình worker xử lý outbox/cleanup tại một thời điểm.

---

## 5 Entrypoints Thực thi (`cmd/`)

- [`cmd/server`](./cmd/server/main.go): Khởi chạy HTTP server daemon (mặc định cổng `:8080`).
- [`cmd/worker`](./cmd/worker/main.go): Khởi chạy tiến trình nền xử lý Transactional Outbox và scheduled cleanup.
- [`cmd/migrate`](./cmd/migrate/main.go): Áp dụng các file migration SQL vào database theo thứ tự tăng dần.
- [`cmd/bootstrap-admin`](./cmd/bootstrap-admin/main.go): Lệnh CLI tạo quyền, role mặc định và khởi tạo tài khoản Super Admin ban đầu.
- [`cmd/avatar-migrate`](./cmd/avatar-migrate/main.go): Lệnh batch migration chuyển file avatar từ local filesystem sang S3.

---

## Hướng dẫn Chạy Local

### Yêu cầu
- Go 1.26+
- Docker & Docker Compose

### Các bước thực hiện

```powershell
# 1. Khởi động MySQL (3306), Redis (6379) và Mailpit (8025/1025)
docker compose up -d

# 2. Tạo file cấu hình môi trường
Copy-Item .env.example .env

# 3. Chạy migration tạo 16 bảng dữ liệu
go run ./cmd/migrate

# 4. Khởi tạo tài khoản Super Admin đầu tiên
$env:UAM_BOOTSTRAP_ADMIN_PASSWORD = "AdminPassword123!@#"
go run ./cmd/bootstrap-admin `
  --username admin `
  --email admin@example.com `
  --full-name "Super Administrator" `
  --phone "0900000000" `
  --date-of-birth "2000-01-01"
Remove-Item Env:UAM_BOOTSTRAP_ADMIN_PASSWORD

# 5. Khởi chạy Background Worker (mở terminal riêng)
go run ./cmd/worker

# 6. Khởi chạy HTTP API Server (mở terminal riêng)
go run ./cmd/server
```

### Địa chỉ dịch vụ khi chạy
- API Base URL: `http://localhost:8080`
- Healthcheck: `http://localhost:8080/health` (Liveness) & `http://localhost:8080/health/ready` (Readiness)
- Swagger UI: `http://localhost:8080/swagger/index.html` (chỉ bật khi `APP_ENV=development`)
- Mailpit UI (xem email OTP gửi đi): `http://localhost:8025`

---

## Tài khoản Test

| Tài khoản | Email | Mật khẩu mặc định | Vai trò |
| :--- | :--- | :--- | :--- |
| **Super Admin** | `admin@example.com` | `AdminPassword123!@#` | `super_admin` (toàn quyền user, role, permission, audit) |
| **Demo User** | `demo@example.com` | `UserPassword123!@#` | `user` (profile, session, TOTP MFA) |

---

## Kiểm thử

```powershell
# Chạy Unit Tests toàn bộ package
go test -short ./...

# Chạy Contract Tests (kiểm tra tương thích toàn bộ 41 public API endpoints)
go test -v ./internal/contract

# Chạy kiểm tra Race Condition
go test -race -count=1 ./...

# Chạy kiểm tra định dạng và vet
gofmt -l .
go vet ./...

# Chạy kiểm thử API tự động qua Newman (Postman Collection)
npx newman run postman_collection.json --insecure
```

---

## CI/CD & Dependabot

Dự án cấu hình sẵn các GitHub Actions workflows tại thư mục `.github/`:
- **[Go CI](.github/workflows/ci.yml)**: Format check, `go vet`, `staticcheck`, `govulncheck`, race detector, cross-compile matrix (Linux/Windows/macOS), integration test MySQL/Redis, và container scan.
- **[CodeQL](.github/workflows/codeql.yml)**: Phân tích ngữ nghĩa mã nguồn Go phát hiện lỗ hổng AST.
- **[Security Audit](.github/workflows/security.yml)**: Quét bảo mật với `gosec` và review dependency pull requests.
- **[Postman API Tests](.github/workflows/postman.yml)**: Tự động chạy container MySQL/Redis, migrate DB, bootstrap admin, start server và chạy Newman test toàn bộ 44 requests.
- **[Release](.github/workflows/release.yml)**: Tự động đóng gói 5 binary cho các hệ điều hành và tạo GitHub Release khi push tag `v*`.
- **[Dependabot](.github/dependabot.yml)**: Tự động quét và gom nhóm PR nâng cấp Go modules, GitHub Actions, Docker base images hàng tuần.
