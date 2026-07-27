# AI Project Instructions (Optimized)

> **MỤC TIÊU**: Xây dựng UAM theo domain-first modular monolith, giữ public HTTP contract và dữ liệu production, đồng thời bảo đảm Concurrency, Security, khả năng scale và xóa sạch legacy sau cutover.

## 1. KHỞI TẠO & ĐỌC CONTEXT (BẮT BUỘC)

- **Đọc Skills (Bước 0)**: Đọc danh sách các `SKILL.md` trước. Chỉ dùng tool `view_file` đọc nội dung các skill thực sự liên quan đến task hiện tại. Chỉ đọc toàn bộ skills khi user yêu cầu audit hoặc thay đổi ảnh hưởng toàn project.
- **Đọc Docs (theo task)**:
    - Thiết kế đích đã duyệt: `docs/superpowers/specs/2026-07-28-domain-first-system-restructure-design.md`.
    - Trong giai đoạn chuyển đổi, `docs/01`…`04` mô tả **as-is**; không dùng chúng để phủ định thiết kế đích.
    - Sau docs cutover, đọc `docs/README.md` để tìm source of truth theo concern:
        - `docs/architecture/`: module, dependency, runtime topology.
        - `docs/domain/`: state invariant và business policy.
        - `docs/data/`: current/target schema, Redis keys, migration.
        - `docs/use-cases/`: semantic use-case graph và public behavior.
        - `docs/operations/`: config, local, deployment, observability.
        - `docs/decisions/`: quyết định kiến trúc còn hiệu lực.
    - Swagger generated hiện ở `docs/docs.go`, `docs/swagger.*`; sau cutover ở `docs/openapi/`. **Không sửa tay**, regenerate bằng `swag`.
    - Quy tắc code/AI workflow: file này (`AGENTS.md`).

## 2. QUY TRÌNH IMPLEMENT (WORKFLOW)

1. **Lên Plan**: Nếu task > 1 file hoặc tính năng mới, tạo outline ngắn (semantic Use Case, file cần sửa/xóa, migration, code tái sử dụng) và đợi user duyệt. Task nhỏ/fix bug thì làm luôn.
2. **Scan Codebase**: Trước khi tạo hoặc xóa file, ưu tiên search/symbol tool của IDE; dùng `rg` khi không có tool phù hợp:
    - Target HTTP: `internal/httpapi/`; legacy: `internal/handler/`, `internal/router/`.
    - Target domain: `internal/auth/`, `account/`, `session/`, `access/`, `accountstate/`; legacy: `internal/service/`.
    - Target adapters: `internal/mysqlstore/`, `redisstore/`, `mail/`, `blob/`, `jobs/`; legacy: `internal/repository/`, `worker/`.
    - Tìm theo semantic use-case ID, route, symbol, table/column, Redis key, env key, test và docs reference.
    - Trước khi xóa, BẮT BUỘC quét toàn repo và lập replacement ledger; không chỉ kiểm tra import Go.
3. **Verification**:
    - Sau khi thay đổi Go source (\*.go), chạy `cmd /c "go build ./..."`. Nếu chỉ sửa docs, config, comment thì không cần build.
    - Nếu có unit test cho phần bị sửa, hãy chạy các test liên quan. Không chạy toàn bộ test suite nếu chỉ thay đổi nhỏ, trừ khi được yêu cầu.
    - Với architecture phase/vertical slice: chạy full `go test ./...`, `go vet ./...`, `staticcheck ./...`, `go mod verify`, `gofmt -l .`, `git diff --check`; concurrency-sensitive code phải có race/integration test phù hợp.
    - Migration phase phải test empty-up và current-data → expand → backfill → cutover → contract trên disposable DB.
    - **Rollback/Fix**: Nếu build hoặc test fail, tự phân tích và fix. Nếu lỗi phức tạp vượt quá phạm vi task, báo lại cho user và xin ý kiến, KHÔNG tự ý sửa lan man.
4. **Cập nhật Docs**:
    - Use case dùng semantic ID (`AUTH-LOGIN`, `ACCOUNT-EMAIL-CHANGE-VERIFY`, v.v.), không tạo UC số mới.
    - Cập nhật đúng source theo concern; không copy cùng một invariant vào nhiều file.
    - BẮT BUỘC cập nhật `PROGRESS.md` khi:
    - Hoàn thành một Feature, Use Case mới.
    - Có thay đổi lớn về API, Database, Architecture.
    - Cập nhật tài liệu quy mô lớn, mang tính toàn cục (VD: Tích hợp Swagger, bổ sung comment/docs cho toàn bộ module).
    *Không cập nhật* nếu chỉ là refactor code nhỏ lẻ, fix bug lặt vặt, sửa lỗi typo hoặc format code thông thường.

## 3. QUY TẮC KIẾN TRÚC & CODE

- **Kiến trúc đích**: `HTTP adapter → domain application use case → domain policy / infrastructure adapter`.
    - Không bắt buộc tạo `Service` hoặc `Repository` type.
    - Package tổ chức theo domain (`auth`, `account`, `session`, `access`), không theo ba layer toàn cục.
    - `httpapi` không chứa business transition; domain không import `httpapi`; store không gọi chéo MySQL/Redis.
    - Transaction thuộc use case. `cmd/*` chỉ wire dependency và lifecycle.
- **Compatibility boundary**:
    - Giữ public route, request/response shape và dữ liệu production.
    - Internal package/API và schema được phép breaking trong vertical slice đã duyệt.
    - Applied migration là bất biến; thay schema bằng migration mới.
- **Comment**: Khi sửa/xóa code, BẮT BUỘC cập nhật hoặc xóa comment cũ liên quan để tránh gây hiểu lầm.
- **Error Handling**:
    - _Lỗi Business_: Dùng `apperror` (VD: `return apperror.ErrNotFound`). Tuyệt đối KHÔNG `fmt.Errorf`.
    - _Lỗi System_: Dùng `fmt.Errorf("...: %w", err)` để bọc lỗi từ tầng dưới.
    - _Ignore Error_: Không bỏ qua lỗi security. Thao tác best-effort thì phải log (`logger.Warn`).
- **Thứ tự Validation & Anti-Spam**:
    1. Format Check (len, regex) -> 2. Rate Limit -> 3. AuthZ (Kiểm tra quyền) -> 4. DB Read -> 5. Bcrypt/Crypto -> 6. DB Write/Tx.
       _(Dùng Token Bucket. Chỉ tính rate limit/failed attempt nếu format hợp lệ)._
- **Security**: Mọi Middleware bảo mật (Auth, Rate limit) phải Fail-Closed (trả về 503 nếu service phụ trợ như Redis sập).
- **State đồng bộ (account/session)** — BẮT BUỘC khi đụng user/auth:
    - Target source: `internal/accountstate/` + `docs/domain/account-state.md`. Trước khi slice này cutover, đọc thêm legacy `internal/service/account_state.go`.
    - Không ghi raw lifecycle/admin-lock/login-lock/password-required field ngoài `accountstate` transition.
    - Đổi password/email/role/account state/MFA → tăng `auth_version` và xóa sessions trong cùng MySQL transaction.
    - Global revoke không phụ thuộc Redis. Logout/revoke một session vẫn blacklist JTI fail-closed.
    - Redis chỉ giữ TTL state: rate/ban/JTI/refresh-reuse/MFA/worker lease; không thêm global revoke hoặc email-change business state mới.
    - Không thêm `safeGo`/`go` trần cho mail. Target là durable outbox + bounded worker; legacy mail path chỉ được giữ tới phase cutover.
    - UC mới/cập nhật phải ghi dependency, transaction, state/session effect, concurrency và failure behavior trong `docs/use-cases/`.

## 4. DATABASE & TRANSACTION

- **Database Migration**:
    - Không tạo migration ngoài task/phase đã được duyệt.
    - Không sửa migration đã deploy. Production dùng forward-only expand → migrate/backfill → cutover → contract.
    - Tách DDL khỏi data backfill; không thêm `NOT NULL`/unique trước khi dữ liệu đã sạch.
    - Không drop cột/table/index trước khi code cũ rời mọi replica và reference sweep sạch.
    - Dữ liệu production phải được preserve, backfill và kiểm tra consistency trước contract.
- **Chống Lost Update**: BẮT BUỘC dùng `FOR UPDATE` (VD: `FindByIDForUpdate(txCtx)`) khi load record để sửa. HOẶC dùng Atomic Update query trực tiếp nếu chỉ đổi trạng thái đơn giản.
- **Transaction owner**: Mọi thao tác nhiều bước thuộc một application use case và nằm trong `TxManager.RunInTx(ctx, func(txCtx) {...})`; không phụ thuộc tên receiver/type cụ thể.
- **Scope Context**:
    - Truyền `txCtx` vào mọi MySQL store call bên trong transaction.
    - KHÔNG gọi MySQL store bằng `ctx` gốc khi đang ở trong `RunInTx`.
    - Redis call đặt ngoài MySQL transaction. KHÔNG lồng các `RunInTx` chồng chéo.
    - Mail/blob/network call đặt ngoài transaction; durable side effect phải ghi outbox trong transaction.

## 5. HÀNH VI CỦA AI (TỐI ƯU OUTPUT)

- **Sử dụng Tool**: Ưu tiên tool chuyên biệt (`grep_search`, `list_dir`, `view_file`). Không lạm dụng lệnh bash (`grep`, `cat`, `ls`) khi đã có tool. Không dùng terminal để đọc file nếu IDE đã có file viewer/search tool. Dùng terminal chủ yếu cho build, test và git.
- **Sửa Code (Targeted Edits & Scope Control)**:
    - **Scope Control**: Chỉ sửa những file bắt buộc cho task. Tuyệt đối không "tiện tay" refactor, rename, move, reformat hoặc đụng chạm tới file/code không liên quan (No opportunistic refactoring).
    - Với vertical refactor đã duyệt, được move/tách/xóa file trong đúng slice; phải xóa legacy counterpart thay vì giữ cả hai.
    - Không tạo file mới chỉ để bọc/forward sang implementation cũ. Tạo package/file mới khi nó là target owner rõ ràng của domain/use case.
    - Chỉ thay đổi chính xác đoạn code cần thiết. TUYỆT ĐỐI KHÔNG rewrite toàn bộ file nếu chỉ sửa 1 đoạn nhỏ.
    - Giữ nguyên định dạng: Không thay đổi formatting của phần code không đụng tới. Không reorder imports trừ khi bắt buộc.
    - Sau cutover, quét và xóa import, DI wiring, symbol, config/env, Redis key, test, comment và docs legacy trong cùng phase.
- **Chống Truncate**: Output phải đầy đủ 100%. KHÔNG để lại `...` hoặc `// rest of code`. Code dài phải ghi thẳng vào file, không paste toàn bộ lên chat.
- **Giao tiếp**: Nói ngắn gọn. Không giải thích code hiển nhiên. Với quyết định kỹ thuật quan trọng, thêm comment ngắn vào code. Khi không chắc chắn về nghiệp vụ/cấu trúc, BẮT BUỘC hỏi lại user trước khi tự quyết định.

## 6. SIMPLICITY FIRST (TRÁNH OVER-ENGINEERING)

- **Consistency First**: Nhất quán với thiết kế đích đã duyệt. Legacy đã được đánh dấu thay thế không phải precedent để copy.
- **Prefer the simplest implementation**: Luôn ưu tiên giải pháp code đơn giản, trực quan nhất.
- **No premature abstraction**: Không tạo Interface/Abstraction cho từng use case. Interface chỉ dùng ở boundary có nhiều implementation hoặc giá trị runtime/test thực tế (chủ yếu mail/blob).
- **No one-time helpers**: Không tạo Helper function nếu nó chỉ được dùng đúng 1 lần (hãy viết thẳng logic inline).
- **Keep files grouped**: Không tách logic lắt nhắt ra nhiều file nhỏ trừ khi nó thực sự cải thiện khả năng bảo trì.
- **Avoid premature optimization**: Tránh tối ưu hóa hiệu suất quá sớm khi chưa có bottleneck thực tế.
- **Minimize changes**: Giữ scope nhỏ theo vertical slice, nhưng không giảm diff bằng cách bỏ lại production path cũ.
- **Reuse first**: BẮT BUỘC tìm và tái sử dụng code/utils/struct hiện có trước khi định tự viết mới.
- **No new dependencies**: Không thêm dependency/package mới nếu thư viện hiện có đã giải quyết được.

## 7. REPLACEMENT DEFINITION OF DONE

Một vertical slice chỉ hoàn thành khi:

1. Public contract test pass và route có đúng một semantic use-case owner.
2. Handler đã chuyển trực tiếp sang implementation mới; không façade giữ service cũ.
3. State/schema read-write path dùng source mới; dual-write chỉ tồn tại trong migration window được ghi rõ.
4. Replacement ledger không còn production symbol, import, DI wiring, Redis key, config/env, comment, docs hoặc test legacy không có owner.
5. Applied migration không bị sửa; backfill/consistency check pass trước contract migration.
6. Build/test/vet/staticcheck/format/diff-check và test concurrency/failure liên quan đều pass.
7. Docs theo concern, route mapping và `PROGRESS.md` được cập nhật đúng mức thay đổi.
