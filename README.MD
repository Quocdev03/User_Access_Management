# User Access Management (UAM) System

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0_InnoDB-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Redis](https://img.shields.io/badge/Redis-7.0_Alpine-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Architecture](https://img.shields.io/badge/Architecture-Modular_Monolith-blueviolet)](#kiến-trúc--nguyên-tắc-thiết-kế)
[![Contract Tests](https://img.shields.io/badge/Contract_Tests-41%2F41_Passing-success)](#kiểm-thử--đảm-bảo-chất-lượng)
[![CI Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?logo=github-actions&logoColor=white)](#kiểm-thử--đảm-bảo-chất-lượng)
[![Dependabot](https://img.shields.io/badge/Dependabot-Active-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Hệ thống quản lý định danh, xác thực và kiểm soát truy cập tập trung (**User Access Management — UAM**) được thiết kế theo kiến trúc **Domain-first Modular Monolith**. Hệ thống được xây dựng tối ưu cho các yêu cầu bảo mật cấp doanh nghiệp: **Concurrency-safe**, **Fail-closed Security**, xoay vòng token tự động (**Refresh Token Rotation & Reuse Detection**) và duy trì tương thích tuyệt đối 41/41 public API contracts.

---

## Mục lục

- [Tính năng & Năng lực cốt lõi](#tính-năng--năng-lực-cốt-lõi)
- [Kiến trúc & Nguyên tắc thiết kế](#kiến-trúc--nguyên-tắc-thiết-kế)
- [Công nghệ & Hạ tầng sử dụng](#công-nghệ--hạ-tầng-sử-dụng)
- [Cài đặt & Khởi chạy nhanh](#cài-đặt--khởi-chạy-nhanh)
- [Tài khoản Demo Khởi tạo sẵn](#tài-khoản-demo-khởi-tạo-sẵn)
- [Tài liệu API & Postman Collection](#tài-liệu-api--postman-collection)
- [Danh mục Entrypoints (cmd/)](#danh-mục-entrypoints-cmd)
- [Kiểm thử & Đảm bảo Chất lượng](#kiểm-thử--đảm-bảo-chất-lượng)
- [Tài liệu Kỹ thuật Chi tiết](#tài-liệu-kỹ-thuật-chi-tiết)

---

## Tính năng & Năng lực cốt lõi

### 1. Quản lý Định danh & Xác thực Toàn diện (Authentication)
- **Đăng ký tài khoản an toàn**: Xác thực mã OTP qua Email với cơ chế chữ ký HMAC-SHA256, chống giả mạo email và tấn công replay.
- **Xác thực Mật khẩu**: Băm mật khẩu bằng Bcrypt (work factor cost 12), hỗ trợ đổi mật khẩu, quên mật khẩu và đặt lại mật khẩu qua email token một lần.
- **Phòng thủ đa tầng chống Brute-Force & DoS**: Token Bucket Rate Limiting trên Redis theo IP và tài khoản, lockout tạm thời khi nhập sai mật khẩu nhiều lần.

### 2. Xác thực Hai yếu tố (Two-Factor Authentication - MFA TOTP)
- **Chuẩn RFC 6238**: Tương thích hoàn toàn với Google Authenticator, Authy, 1Password, Microsoft Authenticator.
- **Bảo mật Secret At-Rest**: Khóa bí mật TOTP được mã hóa bằng **AES-GCM-256** trước khi lưu trữ vào MySQL.
- **Mã khôi phục (Recovery Codes)**: Cấp phát tập mã khôi phục sử dụng một lần (single-use), được băm an toàn chống lộ lọt dữ liệu.

### 3. Phân quyền Dựa trên Vai trò Động (Granular RBAC)
- **Mô hình Role-Permission**: Quản trị vai trò linh hoạt, phân bổ quyền năng động (CRUD User, Role, Permission).
- **Kiểm soát truy cập Fail-closed**: Middleware bảo vệ phân quyền hai lớp tại HTTP handler và domain application service; từ chối truy cập an toàn khi hệ thống phụ trợ gặp sự cố.

### 4. Quản lý Phiên & Phát hiện Tái sử dụng Token (Session & Token Rotation)
- **Refresh Token Rotation (RTR)**: Mỗi lần cấp mới Access Token, Refresh Token hiện tại sẽ bị hủy và thay bằng token mới trong cùng transaction.
- **Phát hiện tái sử dụng (Reuse Detection - RFC 6819)**: Nếu Refresh Token đã bị thu hồi được sử dụng lại, hệ thống ngay lập tức thu hồi toàn bộ cây phiên (`Token Family Revocation`) của người dùng để ngăn chặn kẻ tấn công.
- **Dọn dẹp tự động (Automated Batch Cleanup)**: Worker định kỳ thu hồi và xóa sạch các token đã hết hạn trong `refresh_token_history` theo batch, chống tràn dung lượng và khóa bảng.

### 5. Thu hồi Quyền hạn Tức thì (Instant Revocation)
- **Global Revocation**: Quản lý phiên bền vững qua `auth_version` trên MySQL. Mọi thao tác đổi mật khẩu, đổi email, thu hồi quyền hoặc khóa tài khoản đều tăng `auth_version`, vô hiệu hóa ngay lập tức toàn bộ JWT còn hiệu lực mà không cần chờ JWT expire.
- **Single Session Revocation**: Hỗ trợ đăng xuất từng thiết bị cụ thể qua cơ chế kết hợp MySQL state và Blacklist Access JTI trên Redis với TTL đồng bộ.

### 6. Transactional Outbox & Background Processing
- **Đảm bảo tính nhất quán (Eventual Consistency)**: Email kích hoạt, OTP và sự kiện thông báo được ghi vào bảng `outbox_events` cùng MySQL transaction với thay đổi nghiệp vụ.
- **Worker Tách biệt**: Tiến trình worker độc lập sử dụng distributed lock (Redis lease) để quét outbox, gửi mail qua SMTP với chiến lược exponential backoff và idempotency key.

### 7. Nhật ký Kiểm toán & Giám sát (Audit Trail & Observability)
- **Audit Logging**: Ghi nhận toàn bộ biến động tài khoản (đăng nhập, đổi mật khẩu, gán vai trò, thu hồi quyền, cập nhật hồ sơ) kèm metadata (Client IP, User-Agent, Session ID, Timestamp).
- **Healthcheck & Metrics**: Endpoint `/health` kiểm tra real-time tình trạng kết nối MySQL và Redis.

---

## Kiến trúc & Nguyên tắc thiết kế

Hệ thống tuân thủ nghiêm ngặt các quy chuẩn kiến trúc sạch và an toàn (chi tiết tại [AGENTS.md](./AGENTS.md)):

1. **Luồng phụ thuộc một chiều (Clean Unidirectional Flow)**:
   $$\text{HTTP API (Adapter)} \longrightarrow \text{Domain Application Use Case} \longrightarrow \text{Domain Policy / Storage Adapter}$$
   - Lớp HTTP API chỉ chịu trách nhiệm parse request, validate format và serialize JSON response.
   - Domain logic hoàn toàn độc lập, không phụ thuộc vào framework HTTP (Gin) hay store cụ thể.
   - Thư viện tiện ích (`pkg/`) dùng chung tuyệt đối không import ngược vào `internal/`.
2. **Quyền sở hữu Transaction (TxManager)**:
   - Mọi thao tác ghi nhiều bảng bắt buộc chạy qua `TxManager.RunInTx(ctx, ...)`.
   - Ngăn chặn triệt để Lost Update bằng kỹ thuật khóa dòng bi quan (`FOR UPDATE`) hoặc Atomic SQL statements.
   - Không gọi network I/O (Redis, SMTP, S3) bên trong transaction MySQL; mọi tác vụ ngoại vi đều giao tiếp qua Transactional Outbox.
3. **Thứ tự Middleware Chống DoS (Bắt buộc)**:
   1. `Format & Length Check` (JSON Validator)
   2. `Rate Limit` (Token Bucket Redis)
   3. `Auth & AuthZ` (JWT verify, Permission check)
   4. `Database Read / Lock`
   5. `Crypto / Hash Execution` (Bcrypt, HMAC)
   6. `Database Write / Commit Tx`
4. **Bảo mật Fail-Closed**:
   - Nếu Redis hoặc MySQL gặp sự cố kết nối, các middleware bảo mật sẽ fail-closed và trả về mã lỗi `503 Service Unavailable`, không cho phép request đi tiếp vào lõi hệ thống.

---

## Công nghệ & Hạ tầng sử dụng

| Phân hệ | Công nghệ | Mục đích sử dụng |
| :--- | :--- | :--- |
| **Ngôn ngữ** | Go 1.26 | Lập trình backend lõi, hiệu năng cao, concurrency an toàn |
| **HTTP Framework** | Gin Web Framework | Router tốc độ cao, middleware pipeline chuẩn mực |
| **Cơ sở dữ liệu chính** | MySQL 8.0 (InnoDB) | Lưu trữ quan hệ: Accounts, Roles, Sessions, Outbox, Audit Logs |
| **In-Memory Cache & Lock** | Redis 7.0 (Alpine) | Quản lý Rate Limit, Blacklist JTI, Distributed Worker Leases |
| **Mail Service (Local)** | Mailpit | Giả lập SMTP server và Webmail UI xem mã OTP cục bộ |
| **File / Blob Storage** | Local FS / S3 API | Lưu trữ Avatar người dùng với URL ký hạn giờ |
| **Tài liệu API** | OpenAPI 2.0 / Swagger UI | Tài liệu hóa giao diện RESTful API tự động qua Swag |
| **Kiểm thử API** | Postman v2 / Newman | Bộ sưu tập test case tự động hóa toàn bộ 41 API |

---

## Cài đặt & Khởi chạy nhanh

### Yêu cầu tiên quyết
- [Go 1.26+](https://go.dev/dl/)
- [Docker Desktop](https://www.docker.com/) & Docker Compose

### Các bước khởi chạy môi trường Local

#### Bước 1: Khởi động các container hạ tầng
Khởi chạy MySQL, Redis và Mailpit ở chế độ chạy nền:
```powershell
docker compose up -d
```
> [!NOTE]
> Kiểm tra trạng thái containers: `docker compose ps`. Cả 3 dịch vụ phải ở trạng thái `healthy` hoặc `running`.

#### Bước 2: Cấu hình biến môi trường
Tạo file `.env` từ file mẫu:
```powershell
Copy-Item .env.example .env
```
*(Trên Linux/macOS: `cp .env.example .env`)*

#### Bước 3: Chạy Database Migrations
Áp dụng toàn bộ 34 migrations vào MySQL:
```powershell
go run ./cmd/migrate
```

#### Bước 4: Khởi tạo dữ liệu Quản trị viên ban đầu
Khởi tạo các vai trò mặc định (`super_admin`, `admin`, `user`), danh mục permissions và tài khoản Super Admin:
```powershell
go run ./cmd/bootstrap-admin
```

#### Bước 5: Khởi động Background Worker
Tiến trình worker đảm nhiệm gửi email OTP/Outbox và dọn dẹp định kỳ (chạy ở một terminal riêng):
```powershell
go run ./cmd/worker
```

#### Bước 6: Khởi động API Server
Khởi chạy HTTP API daemon chính (chạy ở một terminal riêng):
```powershell
go run ./cmd/server
```
Server sẽ lắng nghe tại `http://localhost:8080`.

---

## Tài khoản Demo Khởi tạo sẵn

Hệ thống đã cấu hình sẵn hai tài khoản mẫu để phục vụ kiểm thử và trải nghiệm ngay lập tức:

| Vai trò | Email đăng nhập | Mật khẩu mặc định | Quyền hạn |
| :--- | :--- | :--- | :--- |
| **Super Admin** | `admin@example.com` | `AdminPassword123!@#` | Toàn quyền quản trị hệ thống (`super_admin`), quản lý Role, Permission, User, Session |
| **Demo User** | `demo@example.com` | `UserPassword123!@#` | Người dùng thông thường (`user`), quản lý hồ sơ cá nhân, phiên và bảo mật MFA |

---

## Tài liệu API & Postman Collection

### 1. Swagger UI Interactive
Khi biến môi trường `APP_ENV=development`, giao diện Swagger UI được kích hoạt sẵn tại:
- **URL**: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)
- Cho phép xem schema chi tiết và trực tiếp gửi request thử nghiệm trên trình duyệt.

### 2. Mailpit Web Interface (Xem Email OTP)
Mọi email kích hoạt tài khoản, mã xác thực OTP đăng nhập/quên mật khẩu trong môi trường local được bắt trực tiếp tại Mailpit:
- **URL**: [http://localhost:8025](http://localhost:8025)

### 3. Postman Collection v2
Dự án cung cấp sẵn file [`postman_collection.json`](./postman_collection.json) bao gồm đầy đủ **44 API requests** (3 Health/Docs + 41 Nghiệp vụ Domain) với:
- Dữ liệu payload JSON mẫu hợp lệ, sát thực tế.
- Script tự động trích xuất và gán Access Token / Refresh Token vào biến collection sau khi gọi API đăng nhập.
- Tự động tạo timestamp động cho các luồng đăng ký mới.

Bạn có thể chạy toàn bộ bài kiểm tra tự động qua **Newman**:
```powershell
npx newman run postman_collection.json --insecure
```

---

## Danh mục Entrypoints (cmd/)

Dự án cung cấp 5 nhị phân độc lập phục vụ các chức năng riêng biệt, không chồng chéo logic:

- [`cmd/server`](./cmd/server/main.go): HTTP API Server chính phục vụ 41 public API endpoints.
- [`cmd/worker`](./cmd/worker/main.go): Daemon xử lý nền Transactional Outbox (gửi email) và Batch Cleanup (dọn dẹp tokens, audit logs, sessions).
- [`cmd/migrate`](./cmd/migrate/main.go): Công cụ thực thi forward-only database migrations với khả năng kiểm soát phiên bản chính xác.
- [`cmd/bootstrap-admin`](./cmd/bootstrap-admin/main.go): Seed khởi tạo hệ thống, roles, permissions và tài khoản Super Admin ban đầu.
- [`cmd/avatar-migrate`](./cmd/avatar-migrate/main.go): Hỗ trợ chuyển đổi, tối ưu và đồng bộ dữ liệu avatar giữa các kho lưu trữ.

---

## Kiểm thử & Đảm bảo Chất lượng

Quy trình phát triển yêu cầu kiểm tra toàn diện trước khi bàn giao (theo chuẩn Definition of Done tại `AGENTS.md`):

```powershell
# 1. Kiểm tra biên dịch toàn bộ dự án
go build ./...

# 2. Chạy toàn bộ Unit Tests
go test -short ./...

# 3. Chạy toàn bộ Contract Tests (Xác nhận 41/41 API endpoints đạt chuẩn tương thích)
go test -v ./internal/contract

# 4. Kiểm tra phân tích tĩnh mã nguồn
go vet ./...

# 5. Kiểm tra định dạng mã nguồn chuẩn Go
gofmt -l .
```

### Hệ thống CI/CD & Bảo mật Tự động (GitHub Actions)

Dự án tích hợp bộ quy trình GitHub Workflows hoàn chỉnh:
- **[Go CI](.github/workflows/ci.yml)**: Kiểm tra định dạng `gofmt`, `go vet`, `staticcheck`, quét lỗ hổng `govulncheck`, chạy test coverage, kiểm tra tính đồng bộ của OpenAPI docs, biên dịch chéo ma trận đa nền tảng (Linux, Windows, macOS), kiểm tra race condition (`-race`), kiểm thử tích hợp thực tế với disposable MySQL & Redis service containers, và quét lỗ hổng container image bằng Trivy.
- **[CodeQL Analysis](.github/workflows/codeql.yml)**: Phân tích ngữ nghĩa mã nguồn chuyên sâu bởi GitHub CodeQL engine nhằm phát hiện các rủi ro bảo mật tiềm ẩn.
- **[Security Audit](.github/workflows/security.yml)**: Quét AST bảo mật bằng `gosec` và review các thư viện dependency mới thêm vào qua Dependency Review.
- **[Postman API Tests](.github/workflows/postman.yml)**: Tự động dựng hạ tầng database/redis, chạy daemon server và kích hoạt toàn bộ bộ test Postman qua Newman trên mỗi Pull Request.
- **[Automated Release](.github/workflows/release.yml)**: Tự động đóng gói và xuất bản release tar.gz / zip kèm mã hash sha256 cho 5 binary khi gắn tag `v*`.
- **[Dependabot](.github/dependabot.yml)**: Tự động rà soát và tạo Pull Request nâng cấp thư viện Go modules, GitHub Actions và Docker base images hàng tuần có gom nhóm thông minh chống spam.

---

## Tài liệu Kỹ thuật Chi tiết

Để tìm hiểu sâu hơn về kiến trúc và các quyết định kỹ thuật của dự án, vui lòng tham khảo các tài liệu chuyên sâu:

- [Tài liệu Kiến trúc & Điều hướng Kỹ thuật](./docs/README.md)
- [Quy chuẩn Phát triển & Quy tắc AI](./AGENTS.md)
- [Mô hình Trạng thái Tài khoản (Account State)](./docs/domain/account-state.md)
- [Quản lý Phiên & Token Invariants](./docs/domain/session.md)
- [Kiểm soát Truy cập & Ma trận Quyền (RBAC)](./docs/domain/access-control.md)
- [Mô hình Dữ liệu 16 Bảng & Thiết kế Schema](./docs/data/schema-design.md)
- [Quy ước Key & TTL trên Redis](./docs/data/redis-keys.md)
- [Lịch sử Cập nhật & Trạng thái Dự án](./PROGRESS.md)
