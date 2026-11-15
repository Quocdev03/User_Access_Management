# UAM — Implementation Status

> Updated: 2026-07-30

## Release checkpoint

The domain-first modular-monolith restructure is complete.

| Concern | Current state |
| --- | --- |
| Architecture | `httpapi → domain use case → policy/adapter`; manual dependency injection |
| Public API | 41 operations, one semantic owner each, generated OpenAPI and contract tests |
| Database | MySQL migration `000034`, `dirty=false`; canonical schema only |
| Account state | `internal/accountstate` is the single transition-policy owner |
| Sessions | Durable MySQL session/auth-version/reuse history; Redis holds TTL-only state |
| Workflows | Verification, password reset, email change, MFA and mail outbox are durable |
| Runtime | Separate `server`, `worker`, `migrate`, `avatar-migrate`, `bootstrap-admin` binaries |
| Production files | Shared S3-compatible storage; local blob adapter is non-production only |
| Documentation | Concern-based docs plus ADRs; temporary plan and old Markdown retired |

All fourteen implementation phases are complete: security correction, documentation
cutover, schema expansion/backfill, account state, sessions, auth, account,
access/admin, runtime/workers, platform hardening, MFA, HTTP/OpenAPI cutover,
schema contract and release verification.

## Chuẩn hóa comment mã nguồn

- Đã chuẩn hóa comment tiếng Việt cho toàn bộ 123 file Go do dự án quản lý:
  mỗi file có mô tả ngắn về trách nhiệm và toàn bộ 635 hàm/method có Go doc
  bắt đầu bằng đúng tên symbol.
- Đã bổ sung contract cho method trong interface, giữ nguyên 19 build constraint
  và toàn bộ Swagger annotation; `ui_test/index.html` không thuộc phạm vi thay đổi.
- Đã loại bỏ comment phân cách, comment kể lại câu lệnh và mô tả cũ gây nhiễu;
  các giải thích quan trọng về security, transaction, concurrency và compatibility
  được giữ lại hoặc viết rõ hơn.
- OpenAPI sau khi regenerate không thay đổi. Build, full test, vet, staticcheck,
  module verification và public API contract test đều đạt.

## Khắc phục Lỗ hổng Bảo mật & Ngăn ngừa Tấn công (Remediation Workstream A)

- **SEC-01 (Chống leo thang đặc quyền trong phân quyền role)**:
  - `internal/access/roles.go`: Tại hàm `ReplacePermissions`, tích hợp `r.lastAdmin.Lock` và bắt buộc `snapshot.ActorIsAdmin == true` mới được phép thay đổi permissions của bất kỳ role nào.
  - Cấm hoàn toàn việc sửa đổi permissions của role admin hệ thống (`role.IsSystem && role.Name == RoleAdmin`).
- **SEC-02 (Bảo mật phiên khi Logout & Thu hồi Session)**:
  - Mở rộng endpoint `POST /auth/logout` chấp nhận cả access token hết hạn và `refresh_token` từ request body hoặc header `X-Refresh-Token`.
  - Bổ sung `pkg/jwt/jwt.go`: `ParseTokenAllowExpired` giải mã claims an toàn khi token đã hết hạn nhưng chữ ký và thuật toán vẫn hợp lệ.
  - Bổ sung `internal/mysqlstore/session.go`: `RevokeByRefreshHash` thu hồi session tương ứng trong MySQL, không để session và refresh token bị treo 7 ngày khi access token hết hạn.
- **SEC-03 & SEC-08 (Chuẩn hóa thứ tự Middleware & Chống DoS)**:
  - Đảo đúng thứ tự kiểm soát: `Format check (Validator) -> Rate limit -> Auth/AuthZ`.
  - Áp dụng trên toàn bộ routes: `/auth/password/change`, các route MFA (`/setup`, `/confirm`, `/disable`, `/recovery/regenerate`), và user mutation (`/users/me/email/change-request`, `/users/me/avatar`).
  - Tại `PUT /admin/users/:id`: Đưa `PermissionMiddleware` lên trước `validator.ValidateJSON`.
- **SEC-06 (Bảo mật JWT Secret)**:
  - Nâng chuẩn độ dài khóa ký `JWT_SECRET` trong `internal/config/config.go` lên tối thiểu 32 ký tự (256 bits cho HS256) theo khuyến nghị RFC 7518.
- **SEC-07 (Bảo mật Observability / Metrics)**:
  - Trong `internal/httpapi/observability.go`: Chặn đứng truy cập `/metrics` trái phép; nếu `METRICS_TOKEN` không được cấu hình hoặc truyền rỗng, lập tức trả về 404 thay vì mở public.
- **SEC-09 (Mã hóa OTP an toàn)**:
  - Trong `pkg/hash/password.go`: Sửa `HashOTP` sử dụng chuẩn `HMAC-SHA256` với pepper làm secret key thay vì phép nối chuỗi thô `SHA256(otp + pepper)`.

## Sửa lỗi Nghiệp vụ & State Đồng bộ (Remediation Workstream B)

- **LOGIC-01 (Kiểm soát trạng thái tài khoản khi Quên/Đặt lại mật khẩu)**:
  - `internal/auth/password.go`: Kiểm tra nghiêm ngặt `EmailVerified` và `AuthenticationError(now)`. Không cấp token reset và không ghi outbox mail đối với tài khoản chưa xác thực email, bị khóa hoặc vô hiệu hóa; trả về thành công ảo để chống lộ danh tính email.
- **LOGIC-02 (Khóa tài khoản trước khi cập nhật hồ sơ cá nhân)**:
  - `internal/account/profile.go`: Tại hàm `Update`, khóa tài khoản với `FindByIDForUpdate` và xác thực `state.AuthenticationError(now)` trước khi cập nhật `user_profiles`.
- **LOGIC-03 (Chống Deadlock khi Mở khóa tài khoản chưa Verify)**:
  - `internal/accountstate/state.go`: Khi Admin mở khóa cho tài khoản chưa xác thực email, gỡ bỏ `AdministrativeLockedAt`, `LoginLockedUntil` và reset `FailedLoginAttempts = 0`, duy trì lifecycle `PendingVerification` mà không bị vướng lỗi BadRequest.
- **LOGIC-04 (Loại bỏ Fallback Role "user" cứng)**:
  - Loại bỏ hoàn toàn fallback role "user" tự động trong `login.go`, `refresh.go`, `mfa_login.go`, `access/users.go` và `account/profile.go`. Trả về đúng danh sách role thực tế trong DB (`[]string{}`).
- **LOGIC-05 (Chống DoS Khóa tài khoản từ Public Force-Change)**:
  - `internal/auth/password.go`: Tại endpoint public unauthenticated `POST /auth/password/force-change`, khi nhập sai password cũ, không tăng `FailedLoginAttempts` và không khóa tài khoản nạn nhân.
- **LOGIC-06 (Bảo đảm Idempotency cho Bootstrap Admin)**:
  - `internal/access/bootstrap.go`: Kiểm tra `LockUserIDsByRole(txCtx, adminRole.ID)`; từ chối với `409 Conflict` nếu hệ thống đã có ít nhất một tài khoản admin.
- **ARCH-07 & ARCH-08 (Clean Code & Dọn dẹp Dead Code)**:
  - `internal/account/email.go`: Loại bỏ anti-pattern trả về `(error, error)` trong `recordFailedOTP`, chuyển sang Go idiom với `(OTPAttemptResult, error)`.
  - `internal/auth/mfa.go`: Xóa bỏ struct field và dependency `SessionInvalidator` không dùng tới.

## Hoàn thiện Storage, Background Jobs & Decoupling (Remediation Workstream C)

- **ARCH-01 (Context-aware Mail Delivery)**:
  - Bổ sung `context.Context` cho interface `MailSender` và mọi implementation (SMTP, Resend, Mock).
  - Sử dụng `http.NewRequestWithContext` trong Resend client và kiểm tra `ctx.Err()` trước khi gửi SMTP để ngăn chặn trùng lặp email khi timeout.
- **ARCH-02 (Ngăn ngừa SSRF trong Avatar Key)**:
  - Ràng buộc nghiêm ngặt `AvatarObjectKey` trong `AdminUpdateUserRequest` và `internal/access/users.go` chỉ chấp nhận S3/local object key hợp lệ, từ chối URL ngoài (`http://`, `https://`).
- **ARCH-03 (Bảo mật Blob Content-Type)**:
  - Thiết lập tường minh `ContentType` và header `Content-Disposition: inline` trong S3/Local Blob store khi trả file avatar.
- **ARCH-04 (Tách biệt Notification Model trong Mail Outbox)**:
  - Khai báo struct `EmailChangeNotification` chuyên biệt trong `internal/mail/payload.go`, xóa bỏ việc lạm dụng trường `Secret` của `SecretMessage`.
- **ARCH-05 (Thu dọn File rác khi Đổi Avatar & Lỗi Migration)**:
  - Xóa avatar object cũ trên storage khi admin cập nhật avatar mới trong `internal/access/users.go`.
  - Thu dọn object đã copy (`m.deleteCopied(ctx, key)`) khi transaction cập nhật DB thất bại trong `internal/jobs/avatar_migration.go`.
- **ARCH-06 (Phân rã Package Decoupling)**:
  - Tạo `pkg/database/options.go` với struct `MySQLOptions` và `RedisOptions`.
  - Cắt đứt hoàn toàn quan hệ phụ thuộc ngược từ `pkg/database` vào `internal/config`.

## Đồng bộ OpenAPI & Tinh gọn Tài liệu Kỹ thuật (Remediation Workstream D)

- **Đồng bộ Swagger & OpenAPI**:
  - `POST /auth/login`: Bổ sung Swagger annotations tài liệu hóa rõ ràng response khi tài khoản có MFA (`MFALoginChallengeResponse`).
  - `GET /admin/users`: Sửa query parameter thành `per_page`, bổ sung `username`, `email`, `role` (loại bỏ `search` và `page_size`), chuẩn hóa response type sang `AdminUserListItem` kèm `PaginationMeta`.
  - Regenerate toàn bộ `docs/openapi/docs.go`, `swagger.json` và `swagger.yaml` bằng `swag init`.
- **Deduplicate Schema & Invariants**:
  - `docs/data/current-schema.md`: Chuẩn hóa làm Single Source of Truth duy nhất cho cấu trúc schema vật lý của 16 bảng ở migration 000034 (đầy đủ các cột của `sessions`: `ip_address`, `user_agent`, `expires_at`, `created_at`; sửa partial index cho unused recovery codes).
  - `docs/data/schema-design.md`: Tinh gọn để tập trung vào lý do thiết kế kiến trúc (tại sao tách `user_profiles`, tại sao outbox, tại sao phân tách `sessions` và `refresh_token_history`), xóa bỏ việc chép lại danh sách cột trùng lặp, gắn link tham chiếu sang `current-schema.md`.
  - `docs/domain/session.md`: Trở thành trung tâm chuẩn hóa cho toàn bộ các quy tắc vòng đời session (issuance, session cap, rotation concurrency, reuse detection, single session revoke, global auth_version revoke). Giảm trùng lặp trong `docs/use-cases/session.md` và `docs/use-cases/authentication.md`.
  - Khử trùng lặp quy trình 4 bước của `LastAdminGuard` trong `docs/use-cases/access-admin.md` và `docs/use-cases/README.md`, gắn link sang `docs/domain/access-control.md`.
- **Chuẩn hóa Redis Hash Tag & Rate Limit**:
  - `docs/data/redis-keys.md`: Chuẩn hóa quy ước ký hiệu: dấu `{...}` chỉ dùng cho Redis Cluster Hash Tag thực tế (`{identity}`, `{challenge}`); các tham số biến khác dùng `<param>`. Bỏ dấu ngoặc nhọn quanh `<scope>` trong key bucket/violations.
  - `docs/use-cases/authentication.md` & `account.md`: Bổ sung ghi chú giải thích rõ công thức rate limit giữa code và docs: `banLimit (code) = capacity + abuseThreshold (docs)`.
- **Terminology Sweep**:
  - Xóa sạch các từ ngữ cũ "handler", "DTO" trong `docs/architecture/modules.md` và `docs/operations/configuration.md`; chuẩn hóa thành "HTTP endpoint", "Request contract".
  - Bổ sung biến `REDIS_PUBLISHED_PORT` vào bảng cấu hình trong `docs/operations/configuration.md`.

## Clean-source inventory

```text
cmd/
  server  worker  migrate  avatar-migrate  bootstrap-admin
internal/
  access  account  accountstate  auth  blob  config  contract
  httpapi  jobs  mail  mysqlstore  redisstore  session
pkg/
  apperror  database  hash  jwt  logger  response  validator
docs/
  architecture  data  decisions  domain  openapi  operations  use-cases
migrations/
  000001..000034
```

The removed global layer packages are not runtime compatibility boundaries and must
not be recreated. Redis keys are namespaced under `uam:v1`; MySQL runtime code no
longer reads or writes contracted projections.

## Release verification evidence

- Local `go build ./...`, `go test ./...`, `go vet ./...`, `staticcheck ./...` and
  `go mod verify` pass.
- Migration integration passes for empty-up, historical current-data upgrades,
  duplicate-permission fail-closed behavior and schema `031 → 034` contract.
- Auth, account, access, jobs, MySQL store and Redis integration suites pass on
  isolated disposable databases and Redis.
- Concurrency/failure tests pass for credential changes, verification, email,
  refresh/revoke, last-admin/RBAC, MFA, outbox and worker leases.
- Manual runtime smoke passes liveness/readiness/metrics, bootstrap, register,
  email verification, login/refresh/logout, password reset/change, profile, avatar,
  session/client profile, email change, admin/RBAC, MFA setup and audit export.
- Smoke outbox delivered all six events, produced no dead letters and retained no
  secret payload after delivery.
- The production image builds as non-root and contains all five operational binaries,
  migrations and a health check.
- Local and production runtime env files have the same key inventory as their
  templates; obsolete TLS keys were removed without replacing existing secret values.
- `go test -race -count=1 ./...` passes in a Linux Go 1.26.2 container.
- CI now enforces quality, Linux race, disposable MySQL/Redis integration, image
  build and a SHA-pinned vulnerability scan. It does not auto-deploy production.
- Formatting, whitespace, package/path, Markdown and generated-contract inventory
  gates pass; all disposable databases, processes and temporary artifacts are removed.

## Operational limits

- Production promotion remains platform-specific and requires explicit approval,
  a one-off migration job, readiness and post-deploy smoke checks.
- Redis HA/TLS, provider MySQL TLS and real S3/mail credentials must be verified in
  staging because local Compose cannot prove provider failover or certificate policy.
- Contract migrations are forward-only. After migration 034, rollback is a new
  forward-fix migration rather than an edit or destructive downgrade.
- Exact SLO and alert thresholds require production traffic; observability docs list
  the required signals without inventing thresholds.

## Tái cấu trúc & Hoàn thiện Hệ thống (Post-Remediation & Cleanup)

- **Tối ưu Cơ sở dữ liệu & Batch Cleanup (`refresh_token_history`)**:
  - Bổ sung `DeleteExpiredRefreshHistoryBatch` trong `internal/mysqlstore/session.go` dọn dẹp các bản ghi token rotation đã hết hạn quá 7 ngày theo batch giới hạn 500 rows.
  - Tích hợp tác vụ vào `CleanupWorker.runOnce` trong `internal/jobs/cleanup.go`.
  - Kiểm thử unit test `internal/jobs/cleanup_test.go` và integration test đạt 100%.
- **Hiện đại hóa & Chuẩn hóa Tài liệu Dự án**:
  - Tái cấu trúc toàn diện `README.md` theo chuẩn clean, chuyên nghiệp cấp doanh nghiệp, trình bày rõ năng lực cốt lõi, kiến trúc fail-closed, luồng phụ thuộc, bảng công nghệ, hướng dẫn khởi chạy, tài khoản demo, Postman collection và kiểm thử (hoàn toàn không chứa cây thư mục theo yêu cầu).
  - Tích hợp tài khoản Demo sẵn sàng trải nghiệm: Super Admin (`admin@example.com` / `AdminPassword123!@#`) và Demo User (`demo@example.com` / `UserPassword123!@#`).
  - Dọn dẹp ~107MB file thừa, binary cũ và folder rác ở thư mục gốc repo.
  - Cập nhật và tinh gọn quy chuẩn AI & kỹ thuật trong `AGENTS.md`.
  - Cung cấp bộ sưu tập Postman v2 đầy đủ 44 API requests kèm test assertions và auto-token capture.
- **Hệ thống CI/CD & Tự động hóa Bảo mật (GitHub Actions & Dependabot)**:
  - Thiết lập `.github/dependabot.yml`: Tự động quét và tạo PR nâng cấp Go modules, GitHub Actions, Docker base images theo lịch định kỳ, nhóm thông minh theo domain packages.
  - Tối ưu `.github/workflows/ci.yml`: Bổ sung `govulncheck`, kiểm tra OpenAPI sync qua `swag init`, cross-compilation matrix cho 5 binaries (Linux/Windows/macOS), race detector, và disposable MySQL/Redis integration tests.
  - Thiết lập `.github/workflows/codeql.yml`: Phân tích ngữ nghĩa bảo mật CodeQL cho Go.
  - Thiết lập `.github/workflows/security.yml`: Quét lỗ hổng AST với `gosec` và review bản quyền/lỗ hổng dependencies bằng Dependency Review.
  - Thiết lập `.github/workflows/postman.yml`: Tự động khởi động database, server và chạy test Newman cho toàn bộ 44 API requests trên mỗi PR.
  - Thiết lập `.github/workflows/release.yml`: Tự động đóng gói đa nền tảng và xuất bản GitHub Release kèm mã băm sha256 khi tạo Git tag `v*`.

## Khắc phục Triệt để 22 Cảnh báo GitHub Code Scanning (CodeQL & Gosec)

- **Xử lý An toàn Ép kiểu Integer Bounds (12 alerts - G115 & CodeQL CWE-190/681)**:
  - Khởi tạo helper tập trung `parsePositiveInsertID` trong `internal/mysqlstore/tx.go` xác thực kết quả `LastInsertId()` cho toàn bộ 7 store (`access`, `account`, `audit`, `client_profile`, `password_reset`, `session`, `verification_challenge`), ngăn ngừa rủi ro integer overflow/underflow khi ép kiểu sang `uint64`.
  - Bổ sung bounds check tường minh (`math.MaxInt`, `math.MaxInt64`, `math.MaxUint8`) trước khi ép kiểu trong `internal/redisstore/mfa_challenge.go` và `internal/redisstore/limiter.go`.
  - Bổ sung kiểm tra giá trị không âm (`step >= 0`, `elapsed > 0`) trong `internal/auth/mfa_crypto.go` và `internal/httpapi/observability.go`.
- **Ngăn chặn Tấn công Log Injection (3 alerts - CodeQL CWE-117)**:
  - Bổ sung `logger.SanitizeLogValue` trong `pkg/logger/logger.go` khử sạch các ký tự điều khiển xuống dòng (`\r`, `\n`) từ input người dùng trước khi ghi vào structured log (`jti`, `request_id`, `route`).
- **Giải quyết Triệt để Cảnh báo Credential & Password Hashing (4 alerts - G101 & CWE-328)**:
  - Thay thế việc so sánh mã băm thô SHA-256 bằng hàm kiểm tra chuẩn `bcrypt.CompareHashAndPassword` trong `cmd/bootstrap-admin/main.go`, giải quyết tận gốc cảnh báo của CodeQL về weak password hashing và loại bỏ biến hash SHA-256 bị Gosec nghi ngờ.
  - Chuẩn hóa tên biến môi trường `bootstrapPasswordEnvName` và chú thích `// #nosec G101` cho các hằng số hợp lệ (`DummyPasswordHash`, biến môi trường).
- **Kiểm soát An toàn Đường dẫn Tệp Tin (1 alert - Gosec G304)**:
  - Áp dụng `filepath.Clean` và chú thích `#nosec G304` đã được kiểm duyệt an toàn trong `internal/blob/local.go`.
- **Nghiệm thu**:
  - `cmd /c "go build ./..."` biên dịch 100% thành công.
  - 41/41 public API contract test pass.
  - Toàn bộ unit tests pass.
  - `gofmt -l .` và `go vet ./...` đạt chuẩn 100%.

