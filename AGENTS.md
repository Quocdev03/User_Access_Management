# UAM — Hướng dẫn Kỹ thuật & Quy chuẩn Phát triển (AI Guidelines)

> **MỤC TIÊU DỰ ÁN**: Hệ thống User Access Management (UAM) được xây dựng theo kiến trúc **Domain-first Modular Monolith**. Đảm bảo tính toàn vẹn dữ liệu, Concurrency-safe, Fail-closed Security, khả năng scale và giữ vững 41 public API contract.

---

## 1. KHỞI TẠO & ĐỌC CONTEXT

- **Nguồn chân lý tài liệu (Source of Truth theo concern)**:
  - `docs/architecture/`: Ranh giới module, topology runtime, dependency graph.
  - `docs/domain/`: State invariants, lifecycle tài khoản (`account-state.md`), session rules (`session.md`), RBAC (`access-control.md`).
  - `docs/data/`: Schema vật lý 16 bảng (`current-schema.md`), lý do thiết kế (`schema-design.md`), quy ước key Redis (`redis-keys.md`).
  - `docs/use-cases/`: Danh mục 41 semantic use case graph và contract hành vi public.
  - `docs/operations/`: Cấu hình môi trường (`configuration.md`), deployment, observability.
  - `docs/openapi/`: Tài liệu Swagger UI. **Không sửa tay**, tự động regenerate bằng lệnh `swag init`.
- **Ranh giới thư mục mã nguồn**:
  - `cmd/`: 5 entrypoint nhị phân độc lập (`server`, `worker`, `migrate`, `avatar-migrate`, `bootstrap-admin`). Chỉ wire dependency và quản lý lifecycle; không chứa business logic.
  - `internal/`: Chứa các domain module độc lập (`auth`, `account`, `accountstate`, `access`, `session`) và các adapter hạ tầng (`httpapi`, `mysqlstore`, `redisstore`, `mail`, `blob`, `jobs`).
  - `pkg/`: Thư viện tiện ích dùng chung (`apperror`, `database`, `hash`, `jwt`, `logger`, `response`, `validator`). Tuyệt đối không import ngược vào `internal/`.

---

## 2. QUY TRÌNH PHÁT TRIỂN & SỬA ĐỔI (WORKFLOW)

1. **Lập Kế hoạch (Plan)**: Với tính năng mới hoặc task sửa đổi > 1 file, tạo outline ngắn (Use Case semantic ID, file sửa/thêm, migration nếu có) và xác nhận trước khi làm. Bug fix nhỏ có thể triển khai trực tiếp.
2. **Khảo sát Codebase (Targeted Scope)**:
   - Sử dụng tool search (`git grep`, symbol search) theo semantic ID (`AUTH-LOGIN`, `ACCOUNT-PROFILE-UPDATE`...), route hoặc table.
   - Chỉ sửa đổi chính xác các dòng/file thuộc phạm vi task. Tuyệt đối không "tiện tay" refactor, đổi tên, format lại code không liên quan (No opportunistic refactoring).
3. **Quy trình Kiểm thử & Nghiệm thu (Verification)**:
   - Khi sửa file Go: Chạy `cmd /c "go build ./..."` để kiểm tra compile.
   - Chạy unit test của package bị ảnh hưởng: `go test -v ./internal/<package>`.
   - Chạy kiểm tra định dạng và phân tích tĩnh: `gofmt -l .` và `go vet ./...`.
   - Với thay đổi liên quan đến API public: Bắt buộc chạy `go test -v ./internal/contract` (đảm bảo 41/41 contract test pass).
4. **Cập nhật Tài liệu**:
   - Khi hoàn thành Feature mới, thay đổi API, Database hoặc cấu trúc: BẮT BUỘC cập nhật `PROGRESS.md` và tài liệu concern tương ứng trong `docs/`.

---

## 3. QUY TẮC KIẾN TRÚC & CODE CHUẨN MỰC

- **Luồng phụ thuộc một chiều (Clean Boundary)**:
  $$\text{HTTP Endpoint (httpapi)} \longrightarrow \text{Domain Application Use Case} \longrightarrow \text{Domain Policy / Infrastructure Store}$$
  - `httpapi` chỉ validate input và serialize output; không chứa logic chuyển đổi nghiệp vụ (state transitions).
  - Domain không import `httpapi`.
  - Store adapters không gọi chéo giữa MySQL và Redis.
- **Quản lý Lỗi (Error Handling)**:
  - *Lỗi Nghiệp vụ (Business)*: Dùng `apperror` (ví dụ: `return apperror.ErrNotFound`, `apperror.ErrConflict`). Tuyệt đối không dùng `fmt.Errorf`.
  - *Lỗi Hệ thống (System/Infra)*: Dùng `fmt.Errorf("mô tả context: %w", err)` để bọc lỗi từ tầng dưới.
  - *Lỗi Bảo mật*: Tuyệt đối không bỏ qua lỗi. Thao tác best-effort không quan trọng bắt buộc phải ghi log (`logger.Warn`).
- **Thứ tự Middleware & Chống DoS (Bắt buộc)**:
  1. `Format / Length Check` (JSON Validator)
  2. `Rate Limit` (Token Bucket Redis)
  3. `Auth & AuthZ` (JWT verify, Permission check)
  4. `DB Read / Lock`
  5. `Crypto / Hash` (Bcrypt, HMAC)
  6. `DB Write / Commit Tx`
  *(Chỉ tính quota rate limit / failed attempt khi format request hợp lệ).*
- **Quy chuẩn Comment Mã nguồn**:
  - Đầu mỗi file Go: Comment tiếng Việt ngắn nêu rõ file chịu trách nhiệm gì.
  - Trước mỗi named function/method/interface method: Go doc tiếng Việt bắt đầu bằng đúng tên symbol (`// <SymbolName> ...`).
  - Inline comment: Chỉ dùng để giải thích lý do khó thấy (security, concurrency, transaction, fail-closed). Không viết comment chỉ kể lại cú pháp câu lệnh kế tiếp.

---

## 4. QUẢN LÝ DATABASE, TRANSACTION & CONCURRENCY

- **Chủ sở hữu Transaction**:
  - Mọi thao tác ghi nhiều bước phải nằm trong `TxManager.RunInTx(ctx, func(txCtx context.Context) error { ... })`.
  - Bắt buộc truyền `txCtx` vào tất cả các lời gọi MySQL store bên trong transaction. Tuyệt đối không dùng `ctx` gốc trong transaction.
  - Không gọi Redis, Mail, S3 hoặc network I/O bên trong MySQL transaction. Thao tác bất đồng bộ phải ghi outbox event vào MySQL trong transaction.
- **Chống Lost Update**:
  - Bắt buộc dùng `FOR UPDATE` (ví dụ: `FindByIDForUpdate(txCtx)`) khi đọc record để cập nhật, hoặc dùng Atomic Update SQL trực tiếp.
- **Database Migrations**:
  - Migration là bất biến (Forward-only). Tuyệt đối không sửa file migration đã áp dụng.
  - Tách bạch DDL thay đổi cấu trúc bảng khỏi data backfill.

---

## 5. BẢO MẬT & ĐỒNG BỘ TRẠNG THÁI (FAIL-CLOSED)

- **Nguyên tắc Fail-Closed**:
  - Mọi middleware bảo mật (Auth, Rate limit) phải trả về `503 Service Unavailable` nếu service phụ trợ (Redis, MySQL) gặp sự cố.
- **State Policy Duy nhất**:
  - Nguồn chân lý duy nhất cho vòng đời tài khoản là `internal/accountstate/` và `docs/domain/account-state.md`.
  - Không cập nhật trực tiếp các trường lifecycle/lock/password ngoài state machine của `accountstate`.
  - Khi đổi mật khẩu, đổi email, đổi role, thay đổi trạng thái tài khoản hoặc cấu hình MFA: Bắt buộc tăng `auth_version` và thu hồi sessions trong cùng MySQL transaction.
- **Thu hồi Phiên (Session Revocation)**:
  - Thu hồi toàn bộ (Global Revocation) dựa trên `auth_version` bền vững trong MySQL, không phụ thuộc hoàn toàn vào Redis.
  - Thu hồi phiên cụ thể (Single Revoke): Đánh dấu `revoked_at` trong MySQL và blacklist Access JTI vào Redis với TTL tương ứng.

---

## 6. DEFINITION OF DONE (TIÊU CHÍ HOÀN THÀNH)

Một task/feature chỉ được coi là hoàn tất khi:
1. `cmd /c "go build ./..."` biên dịch thành công 100%.
2. `go test -short ./...` và `go test -v ./internal/contract` (41 API contracts) đều pass.
3. `go vet ./...` và `gofmt -l .` không có cảnh báo hay lỗi format.
4. Đầy đủ Go doc tiếng Việt cho các symbol mới hoặc sửa đổi.
5. Không tạo code duplicate, không bọc wrapper thừa thãi.
6. Cập nhật `PROGRESS.md` và tài liệu liên quan trong `docs/`.
