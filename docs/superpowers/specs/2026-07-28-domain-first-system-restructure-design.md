# Design: Domain-First System and Documentation Restructure

**Ngày:** 2026-07-28
**Status:** Approved for planning
**Phạm vi:** Kiến trúc Go, account/auth/session/RBAC/MFA, data model, runtime nhiều replica, toàn bộ `docs/`, quy tắc AI và chiến lược thay legacy
**Compatibility:** Giữ public HTTP contract và dữ liệu production; internal package/API/schema được phép thay qua migration an toàn
**Implementation source:** `plan/architecture-auth-state-consistency-1.md` sẽ được viết lại sau khi spec này được duyệt

---

## 1. Quyết định

UAM được tái cấu trúc thành **domain-first modular monolith, layer nhẹ**. Hệ thống không tiếp tục mở rộng ba thư mục toàn cục `handler/service/repository`, không tách microservice và không giữ hai production path cho cùng một use case.

Luồng dependency chuẩn:

```text
HTTP adapter
  → domain application use case
    → domain policy
      → infrastructure adapter
```

Public routes, request/response shape và dữ liệu người dùng được giữ tương thích. Mọi cấu trúc nội bộ có thể breaking nếu vertical slice chứa đủ migration, cutover, deletion và verification.

### Mục tiêu

1. Một nguồn sự thật rõ ràng cho architecture, data, use case, operations và OpenAPI.
2. Mỗi account/security mutation có transaction boundary và lock order xác định.
3. MySQL giữ durable business/security state; Redis chỉ giữ state ngắn hạn có TTL.
4. API server stateless và có thể chạy nhiều replica.
5. Thay legacy theo vertical slice; chuyển handler xong phải xóa đường cũ trong cùng phase.
6. Tổ chức use case bằng semantic ID và dependency graph, không dùng dãy UC số dễ lệch.
7. Giữ code đơn giản theo idiom Go: manual DI, package có mục đích, không interface/abstraction hàng loạt.

### Không làm

- Không tách auth, account hoặc RBAC thành microservice.
- Không đổi public route hoặc response envelope.
- Không sửa migration đã deploy.
- Không thêm cache cho `auth_version` trước khi có benchmark và stale-consistency contract.
- Không tạo generic base repository/service, event bus tổng quát hoặc interface cho từng use case.

---

## 2. Baseline và các vấn đề hiện tại

### 2.1 Code và HTTP contract

- `internal/service/auth_service.go`: khoảng 1.098 dòng.
- `internal/service/admin_service.go`: khoảng 733 dòng.
- `internal/service/user_service.go`: khoảng 532 dòng.
- `SessionRepository` đang trộn MySQL session với Redis blacklist, revoke epoch, rate limit và email pending.
- Generated Swagger phủ đủ 35/35 operation được mount trong API router tại thời điểm review.
- Baseline ngày 2026-07-28:
  - `go build ./...`: pass.
  - `go test ./...`: pass.
  - `staticcheck ./...`: pass.
  - `go vet ./...`: fail tại SMTP host/port vì `fmt.Sprintf("%s:%d")` không hỗ trợ IPv6.

### 2.2 Documentation

Docs hiện trộn ba thời điểm:

1. Hành vi code đang chạy.
2. Các invariant đã vá gần đây.
3. Kiến trúc tương lai trong master plan.

Các xung đột chính:

- `docs/01` coi use-case docs là nguồn thật, `docs/03` lại coi code hiện tại là nguồn thật.
- Docs còn mô tả `user_revoked_epoch` và Redis email pending trong khi plan chuyển sang `auth_version` và MySQL aggregate.
- `docs/04` hướng dẫn production dùng TLS skip-verify và bootstrap credential công khai.
- Khối Docker Compose bị trộn nội dung Dockerfile; có lệnh `make seed` và service Compose `app` không tồn tại.
- Use-case reference còn `UC-40` dù tài liệu đã renumber.
- Spec MFA dùng `GET challenge → verify → DEL`, cho phép hai verify đồng thời cùng cấp session.

### 2.3 Khả năng scale

Các blocker cho nhiều replica:

- Mọi API instance tự chạy migration.
- Mọi API instance tự chạy cleanup worker.
- Avatar nằm trên local disk.
- Mail chạy bằng goroutine không bounded, không durable và không retry.
- MySQL/Redis pool dùng hằng số, không tính tổng replica.
- Redis là dependency fail-closed nhưng chưa có topology HA trong operations docs.
- Thiếu request ID, metrics, tracing, SLO và deployment topology.

---

## 3. Kiến trúc package đích

```text
cmd/
├── server/
├── worker/
├── migrate/
└── bootstrap-admin/

internal/
├── httpapi/
├── auth/
├── account/
├── session/
├── access/
├── accountstate/
├── mysqlstore/
├── redisstore/
├── mail/
├── blob/
└── jobs/
```

### 3.1 Trách nhiệm

| Package | Trách nhiệm |
| --- | --- |
| `httpapi` | Router, middleware composition, handler, bind/validate, response mapping và Swagger annotations |
| `auth` | Register, verify email, login, refresh, password và MFA use cases |
| `account` | Profile, email change và avatar use cases |
| `session` | Session issue/rotate/revoke/list và observed client profiles |
| `access` | RBAC, admin user mutation, role mutation và last-admin guard |
| `accountstate` | Pure account transition/access policies và effective public status |
| `mysqlstore` | Durable query/command implementations, không gọi Redis/mail/blob |
| `redisstore` | Token bucket, ban, JTI blacklist, refresh-reuse marker và atomic MFA challenge |
| `mail` | Mail rendering/provider adapter |
| `blob` | Avatar/object storage adapter |
| `jobs` | Outbox delivery, cleanup và scheduled maintenance |

### 3.2 Dependency rules

- `httpapi` gọi domain use case; không chứa business state transition.
- Domain module không import `httpapi`.
- Domain module có thể dùng concrete store khi chỉ có một implementation.
- Interface chỉ đặt tại boundary có nhiều implementation hoặc cần thay runtime adapter, chủ yếu mail/blob.
- `mysqlstore` và `redisstore` không gọi lẫn nhau.
- Transaction được mở và sở hữu bởi application use case.
- Không gọi Redis, mail hoặc blob trong MySQL transaction.
- Không để domain module gọi vòng nhau; shared invariant đặt ở `accountstate`, shared session capability đặt ở `session`.
- `cmd/*` chỉ parse config, wire dependency, quản lý lifecycle và gọi package nội bộ.

### 3.3 File grouping

Không tạo folder con cho từng handler/service/repository. Mỗi domain package nhóm file theo use case:

```text
internal/auth/
├── register.go
├── email_verification.go
├── login.go
├── refresh.go
├── password.go
├── mfa.go
└── *_test.go
```

---

## 4. Canonical account model

### 4.1 State trực giao

`users.status` hiện tại đang gánh email verification, admin disable và brute-force lock. Model mới tách:

```text
users
├── lifecycle_state          pending_verification | active | disabled
├── email_verified
├── administrative_locked_at
├── login_locked_until
├── failed_login_attempts
├── password_change_required
├── auth_version
└── identity/security timestamps
```

Public API vẫn trả `active | inactive | locked`:

```text
administrative_locked_at != NULL → locked
login_locked_until > now         → locked
lifecycle_state != active        → inactive
còn lại                          → active
```

`accountstate` là nơi duy nhất tính effective status và chuyển state. Không ghi trực tiếp các field trên từ use case.

### 4.2 Profile

`user_profiles` tách full name, phone, date of birth và avatar object key khỏi security-hot row:

```text
user_profiles
├── user_id PK/FK
├── full_name
├── phone
├── date_of_birth
├── avatar_object_key
└── updated_at
```

Profile update không cần tranh chấp account security row nếu không thay identity/security data.

---

## 5. Current database assessment

Schema hiện tại có 10 bảng nghiệp vụ và dùng InnoDB, `utf8mb4`, FK, unique key, hashed OTP/token. Nền tảng này được giữ, nhưng các boundary sau phải đổi.

| Bảng/nhóm hiện tại | Đánh giá | Quyết định |
| --- | --- | --- |
| `users` | Trộn identity, profile, credential và nhiều loại state | Tách profile; thay state bằng model trực giao |
| `roles`, `permissions` | RBAC cơ bản đúng | Giữ; thêm system metadata và unique `(resource, action)` |
| `user_roles`, `role_permissions` | N–N đúng | Giữ |
| `sessions` | JTI nullable; reuse detection phụ thuộc Redis | JTI bắt buộc; thêm durable refresh history |
| `devices` | Unique `(user, os, browser)` không phải device identity | Bỏ unique giả; đổi semantics thành observed client profile |
| `otp_codes` | ENUM purpose; không gắn workflow/request | Thay bằng request-scoped verification challenge |
| `password_reset_tokens` | Thiếu auth version và consumed timestamp | Mở rộng |
| `audit_logs` | Append model ổn; FK `RESTRICT` cản anonymize/delete user | Giữ log, đổi user FK sang `SET NULL` |
| Email change | State chia MySQL và Redis | Thêm MySQL aggregate |
| Outbox/MFA | Chưa tồn tại | Thêm mới |

### 5.1 RBAC

- `roles.is_system` đánh dấu `admin`, `moderator`, `user`.
- `permissions` có unique `(resource, action)` sau khi kiểm tra duplicate.
- Last-admin mutation lock row role `admin` trước khi đếm admin usable.
- Role/session/auth state mutation dùng cùng transaction và tăng `auth_version`.

### 5.2 Session và refresh history

```text
sessions
├── id, user_id
├── current_refresh_hash
├── access_jti NOT NULL
├── client_profile_id
├── expires_at, revoked_at
└── created_at, updated_at

refresh_token_history
├── token_hash UNIQUE
├── session_id, user_id
├── rotated_at
└── expires_at
```

Refresh reuse được nhận diện bằng MySQL ngay cả khi Redis restart. Redis marker có thể giữ để fast reject nhưng không là durable source.

### 5.3 Security workflow tables

```text
verification_challenges
├── id
├── purpose VARCHAR
├── subject_type, subject_id
├── secret_hash
├── attempts
├── consumed_at
├── expires_at
└── created_at

email_change_requests
├── id, user_id
├── old_email, new_email
├── auth_version
├── state
├── expires_at
└── timestamps

password_reset_tokens
├── id, user_id
├── token_hash
├── auth_version
├── consumed_at
├── expires_at
└── created_at
```

Email-change challenge tham chiếu request ID. Request, challenge và account snapshot được tạo trong cùng MySQL transaction.

### 5.4 MFA

- `user_totp`: encrypted secret, enabled/confirmed timestamps và encryption key version.
- `user_totp_recovery_codes`: one-time hash, used timestamp.
- MFA login challenge chỉ ở Redis, chứa user ID, auth version, attempts và TTL.
- Challenge verify/consume dùng atomic Redis operation; không dùng `GET` rồi `DEL`.

### 5.5 Audit, outbox và avatar

- Security audit của mutation thành công được append trong transaction.
- `outbox_events` lưu mail/event durable; bounded worker claim theo batch, retry/backoff và dead-letter metadata.
- User/profile chỉ lưu `avatar_object_key`.
- Local filesystem là development blob adapter; production dùng object storage.

---

## 6. Data transition map

### 6.1 Account state backfill

| State cũ | State mới |
| --- | --- |
| `active` | `lifecycle_state=active` |
| `inactive + email_verified=false` | `pending_verification` |
| `inactive + email_verified=true` | `disabled` |
| `locked + locked_until IS NULL` | `administrative_locked_at=updated_at` |
| `locked + locked_until != NULL` | `login_locked_until=locked_until` |
| `must_change_password=true` | `password_change_required=true` |

Application dual-write schema cũ/mới trong migration window. Contract migration chỉ chạy sau consistency query xác nhận không còn mismatch.

### 6.2 Session

- Session có `jti IS NULL OR jti=''` được revoke bằng `auth_version` rồi xóa trước khi set `NOT NULL`.
- Existing refresh token tiếp tục dùng được.
- Refresh history chỉ có dữ liệu từ cutover; token rotate trước cutover không thể tái tạo.
- `user_revoked_epoch` chỉ bị xóa sau khi mọi JWT mới có `auth_version` và contract tests pass.

### 6.3 OTP/email/reset

- OTP đang sống được drain theo TTL hoặc invalidate có chủ đích tại cutover; không cố migrate workflow dở dang.
- Redis email pending bị xóa; user đang đổi email phải request lại.
- Password reset token cũ được invalidate khi thêm `auth_version`.

### 6.4 Device/avatar

- Giữ device rows còn tồn tại; dữ liệu đã bị dedupe bởi migration 018 không thể khôi phục.
- Drop unique `(user_id, os, browser)` sau khi code không còn phụ thuộc.
- Avatar file được copy và checksum vào blob store trước khi chuyển read path; record chỉ đổi sang object key sau copy thành công.

### 6.5 RBAC/audit/bootstrap

- Backfill `is_system` theo role name đã seed.
- Kiểm tra duplicate trước khi tạo unique permission `(resource, action)`.
- Audit FK chuyển sang `ON DELETE SET NULL`, không xóa log.
- Corrective migration chỉ xóa bootstrap account khi email/username và known password hash đều còn nguyên. Account đã đổi hash được đưa vào operator audit, không tự xóa.

---

## 7. Migration strategy

Production dùng forward-only expand/migrate/contract:

```text
1. Security correction
2. Expand account/profile schema
3. Batched data backfill
4. Deploy dual-write/read-new
5. Expand session/challenge/RBAC/outbox schema
6. Cutover từng vertical slice
7. Consistency verification
8. Contract migration xóa cột/index/path cũ
```

Quy tắc:

- Migration đã deploy là immutable.
- DDL và data backfill nằm ở migration/job riêng.
- Không thêm `NOT NULL` vào bảng có dữ liệu trước khi backfill.
- Không drop cột/table trước khi application version cũ rời toàn bộ replica.
- Migration lớn được thử trên production-sized copy và đo lock time.
- Production rollback là forward-fix migration.
- Mỗi migration có rollback/irreversibility note.

---

## 8. Redis contract

Redis chỉ giữ state ngắn hạn có TTL:

```text
uam:v1:rate:{scope}:{identity}
uam:v1:ban:{identity}
uam:v1:jti:{jti}
uam:v1:refresh-reuse:{hash}
uam:v1:mfa:{challenge}
uam:v1:worker-lease:{job}
```

Không còn:

- `user_revoked_epoch`.
- `email_change_pending`.
- Business state cần compensation với MySQL.

Security path dùng Redis phải fail-closed. Mail/outbox/cleanup không làm API transaction thất bại vì Redis.

---

## 9. Runtime topology

```text
Load balancer
  → N × cmd/server
       → MySQL primary
       → Redis HA
       → object storage

1 × cmd/worker (hoặc distributed lease)
  → outbox delivery
  → cleanup

Deployment job
  → cmd/migrate

Operator one-off
  → cmd/bootstrap-admin
```

### Runtime rules

- API server không tự migrate hoặc start cleanup worker.
- API process stateless; không phụ thuộc local uploads.
- MySQL/Redis pool cấu hình qua env và budget theo tổng replica.
- Liveness không phụ thuộc backing service.
- Readiness kiểm tra MySQL/Redis nhưng không đi qua client IP ban/rate limiter.
- Graceful shutdown chờ HTTP inflight; worker ngừng claim mới và hoàn tất/nhả lease.
- Mail outbox dùng bounded concurrency, retry/backoff và idempotency key.

### Auth version

Middleware đọc `auth_version` từ MySQL bằng primary key trong correctness-first release. Cache chỉ được thêm khi có:

- Benchmark chứng minh DB là bottleneck.
- Stale window được định nghĩa.
- Cache invalidation/fallback semantics rõ ràng.
- Tests chứng minh token không sống ngoài stale window đã duyệt.

---

## 10. Semantic use-case system

### 10.1 Quan hệ

Mỗi use case ghi riêng:

- Journey prerequisite.
- Capability dependency.
- State consequence.

Use case không gọi handler và không tạo dependency cycle. Shared capability không được giả thành public use case.

### 10.2 Shared capabilities

- `AccountAccessPolicy`
- `CredentialPolicy`
- `AccountTransitionPolicy`
- `LastAdminGuard`
- `AuthInvalidator`
- `SessionIssuer`
- `SessionRotator`
- `ChallengeIssuer`
- `ChallengeConsumer`
- `AuditAppender`
- `OutboxEnqueuer`

### 10.3 Public operation mapping

Các path trong bảng dưới đây tương đối với base path `/api/v1`.

| Semantic ID | Operation |
| --- | --- |
| `AUTH-REGISTER` | `POST /auth/register` |
| `AUTH-EMAIL-VERIFY` | `POST /auth/email/verify` |
| `AUTH-EMAIL-RESEND` | `POST /auth/email/resend` |
| `AUTH-LOGIN` | `POST /auth/login` |
| `AUTH-TOKEN-REFRESH` | `POST /auth/token/refresh` |
| `AUTH-LOGOUT` | `POST /auth/logout` |
| `AUTH-LOGOUT-ALL` | `POST /auth/logout-all` |
| `AUTH-PASSWORD-FORGOT` | `POST /auth/password/forgot` |
| `AUTH-PASSWORD-RESET` | `POST /auth/password/reset` |
| `AUTH-PASSWORD-CHANGE` | `POST /auth/password/change` |
| `AUTH-PASSWORD-FORCE-CHANGE` | `POST /auth/password/force-change` |
| `ACCOUNT-PROFILE-GET` | `GET /users/me` |
| `ACCOUNT-PROFILE-UPDATE` | `PATCH /users/me` |
| `ACCOUNT-EMAIL-CHANGE-REQUEST` | `POST /users/me/email/change-request` |
| `ACCOUNT-EMAIL-CHANGE-VERIFY` | `POST /users/me/email/verify` |
| `ACCOUNT-EMAIL-CHANGE-RESEND` | `POST /users/me/email/resend` |
| `ACCOUNT-AVATAR-UPLOAD` | `POST /users/me/avatar` |
| `ACCOUNT-AVATAR-DELETE` | `DELETE /users/me/avatar` |
| `SESSION-LIST` | `GET /users/me/sessions` |
| `SESSION-REVOKE` | `DELETE /users/me/sessions/{id}` |
| `CLIENT-PROFILE-LIST` | `GET /users/me/devices` |
| `ACCESS-USER-LIST` | `GET /admin/users` |
| `ACCESS-USER-GET` | `GET /admin/users/{id}` |
| `ACCESS-USER-UPDATE` | `PUT /admin/users/{id}` |
| `ACCESS-USER-STATUS-CHANGE` | `PATCH /admin/users/{id}/status` |
| `ACCESS-USER-PASSWORD-RESET` | `POST /admin/users/{id}/password/reset` |
| `ACCESS-USER-NOTIFY` | `POST /admin/users/{id}/notify` |
| `ACCESS-ROLE-LIST` | `GET /admin/roles` |
| `ACCESS-ROLE-CREATE` | `POST /admin/roles` |
| `ACCESS-ROLE-UPDATE` | `PUT /admin/roles/{id}` |
| `ACCESS-ROLE-DELETE` | `DELETE /admin/roles/{id}` |
| `ACCESS-ROLE-PERMISSIONS-REPLACE` | `PUT /admin/roles/{id}/permissions` |
| `ACCESS-ROLE-ASSIGN` | `POST /admin/users/{id}/roles` |
| `ACCESS-ROLE-REMOVE` | `DELETE /admin/users/{id}/roles/{roleId}` |
| `AUDIT-EXPORT` | `GET /admin/audit-logs/export` |

Ngoài 35 Swagger operations:

- `SYSTEM-LIVENESS`: `GET /health`.
- `SYSTEM-READINESS`: `GET /health/ready`.

MFA additions:

- `MFA-LOGIN-VERIFY`
- `MFA-SETUP`
- `MFA-CONFIRM`
- `MFA-DISABLE`
- `MFA-STATUS`
- `MFA-RECOVERY-REGENERATE`

### 10.4 Journey graph

```text
AUTH-REGISTER
→ AUTH-EMAIL-VERIFY
→ AUTH-LOGIN
→ MFA-LOGIN-VERIFY (nếu bật)
→ SessionIssuer
```

```text
AUTH-PASSWORD-FORGOT
→ AUTH-PASSWORD-RESET
→ AuthInvalidator
→ AUTH-LOGIN
```

```text
ACCESS-USER-PASSWORD-RESET
→ one-time reset link
→ AUTH-PASSWORD-RESET
→ AuthInvalidator
```

`AUTH-PASSWORD-FORCE-CHANGE` chỉ phục vụ record legacy đang có `password_change_required`; bootstrap/admin reset mới không tạo temp-password flow.

```text
ACCOUNT-EMAIL-CHANGE-REQUEST
→ ACCOUNT-EMAIL-CHANGE-RESEND (optional)
→ ACCOUNT-EMAIL-CHANGE-VERIFY
→ AuthInvalidator
```

```text
MFA-SETUP
→ MFA-CONFIRM
→ AUTH-LOGIN
→ MFA-LOGIN-VERIFY
→ SessionIssuer
```

```text
ACCESS-ROLE-ASSIGN / ACCESS-ROLE-REMOVE
→ LastAdminGuard
→ role mutation
→ AuthInvalidator
```

### 10.5 Use-case document template

Mỗi semantic use case phải ghi:

1. ID và public endpoint.
2. Actor/authentication.
3. Journey prerequisites.
4. Capability dependencies.
5. Validation/rate-limit order.
6. Transaction và lock order.
7. State transition.
8. Session/auth-version effect.
9. Audit/outbox side effects.
10. Concurrency collisions.
11. Failure/idempotency behavior.
12. Related schema và tests.

---

## 11. Documentation information architecture

```text
docs/
├── README.md
├── architecture/
│   ├── system-context.md
│   ├── modules.md
│   ├── runtime-topology.md
│   └── security-boundaries.md
├── domain/
│   ├── account-state.md
│   ├── authentication.md
│   ├── session.md
│   └── access-control.md
├── data/
│   ├── current-schema.md
│   ├── target-schema.md
│   ├── redis-keys.md
│   └── migration-strategy.md
├── use-cases/
│   ├── README.md
│   ├── authentication.md
│   ├── account.md
│   ├── session.md
│   ├── access-admin.md
│   └── mfa.md
├── operations/
│   ├── local-development.md
│   ├── configuration.md
│   ├── deployment.md
│   └── observability.md
├── decisions/
└── openapi/
    ├── docs.go
    ├── swagger.json
    └── swagger.yaml
```

### 11.1 Source of truth theo concern

| Concern | Source |
| --- | --- |
| Architecture/dependency | `docs/architecture/` |
| Domain invariant | `docs/domain/` + invariant tests |
| Current/target schema | migrations + `docs/data/` |
| Public business behavior | `docs/use-cases/` + contract tests |
| Config/deployment | config validation + env templates + `docs/operations/` |
| Design decisions | `docs/decisions/` |
| HTTP generated reference | `docs/openapi/` |
| Execution status | master plan |

Generated Swagger không sửa tay. `docs/use-cases/README.md` chứa dependency DAG, mapping đủ route và bảng legacy UC ID → semantic ID trong migration window.

### 11.2 Retiring old docs

- Nội dung còn đúng được nhập vào destination mới và ghi vào reconciliation table `old file/section → new owner`.
- Nội dung current-state và target-state không nằm chung một đoạn không gắn nhãn.
- File cũ bị xóa sau khi destination, link và coverage check đã hoàn tất; không giữ redirect stub.
- Không giữ `archive/`, `legacy/`, `.bak.md` hoặc bản copy lịch sử trong repo; Git history là nơi lưu lịch sử.

Deletion manifest bắt buộc:

| Legacy Markdown | Điều kiện trước khi xóa | Destination |
| --- | --- | --- |
| `docs/01-architecture.md` | Module, middleware, state invariant và runtime đã được đối soát | `docs/architecture/*`, `docs/domain/account-state.md` |
| `docs/02-database-design.md` | Current schema, target schema, Redis keys và migration map đã đầy đủ | `docs/data/*` |
| `docs/03-use-cases.md` | Đủ mapping 35 operations, semantic IDs và dependency graph | `docs/use-cases/*` |
| `docs/04-environment-setup.md` | Local/config/deployment/mail instructions đã được verify với executable files | `docs/operations/*` |
| `docs/superpowers/specs/2026-07-16-2fa-totp-design.md` | MFA decisions đã nhập vào domain/use-case/ADR mới và race GET/DEL đã bị loại | `docs/domain/authentication.md`, `docs/use-cases/mfa.md`, `docs/decisions/*` |

Sau khi kiến trúc mới đã được triển khai và quyết định domain-first được ghi thành ADR, spec hiện tại cũng được retire:

| Transitional Markdown | Xử lý cuối |
| --- | --- |
| `docs/superpowers/specs/2026-07-28-domain-first-system-restructure-design.md` | Nhập quyết định còn hiệu lực vào `docs/decisions/` và các source theo concern, rồi xóa |

Final docs tree không chứa `docs/superpowers/`. Không có hai file Markdown cùng sở hữu một rule.

Deletion gate:

1. Reconciliation table không còn section chưa có destination.
2. Route/use-case coverage vẫn là 35/35 và MFA additions có owner.
3. `rg` toàn repo không còn reference tới legacy path.
4. Markdown inventory chỉ chứa allowlist của docs tree mới.
5. `git diff --name-status` thể hiện legacy files bị xóa, không phải giữ lại với banner “deprecated”.

---

## 12. Vertical replacement protocol

Mỗi vertical slice thực hiện:

1. **Inventory:** route, handler, service, repo, model, table/column, Redis key, config, test, docs, comment và DI wiring.
2. **Contract lock:** test request/response/status/side effect cần giữ.
3. **Expand:** schema/package mới backward-compatible.
4. **Replace:** implement use case mới và chuyển handler trực tiếp.
5. **Delete:** xóa production path, symbol, key, config, test/comment/docs legacy.
6. **Verify:** reference sweep, build, test, vet, staticcheck, concurrency/failure tests.

Không hoàn thành phase nếu:

- Hai production path xử lý cùng use case.
- Handler còn gọi façade chỉ để giữ service cũ.
- Redis key/config/comment cũ còn reference không có owner.
- Migration/schema mới tồn tại nhưng read/write path vẫn dùng nguồn cũ.
- Net production code tăng vì giữ implementation cũ thay vì thay thế.
- Legacy Markdown còn tồn tại dưới dạng stub/archive/copy sau khi destination đã hoàn tất.

Shim tạm chỉ được phép khi rollout nhiều phiên bản bắt buộc, phải có owner, expiry và deletion task trong cùng phase hoặc phase contract ngay sau đó.

---

## 13. Testing strategy

### Contract

- Snapshot 35 HTTP operations: method/path, auth, request validation, response envelope/status.
- Generated Swagger operation coverage phải bằng router operation coverage.
- Contract tests giữ API trong khi internal package được thay.

### Domain

- Table-driven tests cho account effective status và mọi transition.
- Property/invariant tests cho không tồn tại state combination bất hợp lệ.
- Last-admin tests với concurrent status/role mutation.

### Persistence/migration

- Empty DB up.
- Current schema/data fixture → expand → backfill → cutover → contract.
- Consistency query trước drop.
- Production-sized migration timing và lock observation.
- Session/JTI, refresh history, email request/challenge và outbox integration tests.

### Concurrency/failure

- Login cạnh tranh password/status/MFA change.
- OTP resend/verify chỉ một challenge thắng.
- MFA challenge atomic consume.
- Refresh reuse và dual refresh.
- Redis down trên security path.
- Mail provider down sau business commit.
- Worker duplicate claim/lease expiry.

### Verification

- `go build ./...`
- `go test ./...`
- `go test -race ./...` trên CI Linux.
- `go vet ./...`
- `staticcheck ./...`
- `go mod verify`
- `gofmt -l .`
- `git diff --check`

---

## 14. Risks and decisions

| Risk | Mitigation |
| --- | --- |
| Refactor quá rộng | Chia vertical slice và giữ một master dependency graph |
| Dual-write drift | Consistency query, bounded migration window, contract phase |
| DB read `auth_version` tăng tải | Correctness-first, benchmark trước cache |
| Profile split làm tăng join | Profile chỉ join ở profile/admin views; auth query không cần profile |
| Outbox tăng schema/worker complexity | Giới hạn event type cho mail/security notification |
| Device semantics thay đổi | Giữ API, document observed client profile, không hứa physical identity |
| Old replicas dùng schema cũ | Expand-contract và rollout order |
| Docs lại phân kỳ | Source-of-truth table, route coverage và invariant tests |

### Alternatives rejected

- Giữ global `handler/service/repository`: đã tạo mega-service và cross-folder change.
- Big-bang rewrite: khó chứng minh parity và migration safety.
- Legacy façade chạy song song lâu dài: làm code phình và tạo hai nguồn logic.
- Microservices: tăng distributed transaction/ops cost khi domain boundary chưa ổn.
- Redis làm durable account state: không atomic với MySQL.
- Cache auth version ngay: tạo stale revocation trước khi có nhu cầu đo được.

---

## 15. Acceptance criteria

- Kiến trúc package, data model, use-case IDs và docs tree có một nguồn mô tả thống nhất.
- Public 35-operation contract được giữ bằng tests.
- Mọi route có đúng một semantic use-case owner.
- MySQL là nguồn durable cho account/session/security workflow.
- Redis không còn global revoke epoch hoặc email-change business state.
- API server không tự migrate, chạy cleanup hoặc giữ local production file.
- Mỗi vertical slice xóa legacy path trước khi hoàn thành.
- Legacy Markdown trong deletion manifest bị xóa; final `docs/` không chứa stub/archive hoặc `superpowers/`.
- Applied migrations không bị sửa; dữ liệu production được backfill/verify trước contract.
- `AGENTS.md` không còn ép code mới vào global service/repository layout.
- Master implementation plan được viết lại từ spec này sau user review.
