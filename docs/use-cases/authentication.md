# Authentication Use Cases

All API operations pass a coarse global token bucket. Public sensitive operations
first validate JSON format/byte bounds, then use an atomic per-route token bucket.
The rate column is `capacity / rejected-valid-request abuse threshold` for the
configured one-minute refill window. Reaching the abuse threshold bans the identity
for the configured ban duration. Security Redis errors fail closed.

> [!NOTE]
> **Công thức cấu hình Rate Limit giữa Code và Docs**:
> Cột *Per-route rate* trong bảng dưới đây được ghi theo quy chuẩn `capacity / abuseThreshold` (ví dụ `10/20` nghĩa là capacity = 10 tokens và ngưỡng vi phạm abuseThreshold = 20 rejected requests). Trong mã nguồn Go (`internal/httpapi/auth_routes.go`), tham số `banLimit` truyền vào middleware rate limit tính theo công thức:
> `banLimit (code) = capacity + abuseThreshold (docs)`
> Vì vậy, định nghĩa `10/20` trong tài liệu tương ứng chính xác với lời gọi `rateLimit(name, 10, 30)` trong code (10 + 20 = 30). Tương tự, `15/35` ứng với `(15, 50)` và `30/30` ứng với `(30, 60)`.

## Operation contracts

| ID | Auth | Per-route rate | Core behavior |
| --- | --- | --- | --- |
| AUTH-REGISTER | Public | `10/20` | Validate unique email/username; create inactive user, user role, hashed challenge and durable mail event transactionally |
| AUTH-EMAIL-VERIFY | Public | `10/20` | Consume hashed OTP with attempt/expiry check, verify email and activate eligible account |
| AUTH-EMAIL-RESEND | Public | `10/20` | Replace the active challenge and enqueue durable mail delivery; missing/already-verified accounts keep the generic success boundary |
| AUTH-LOGIN | Public | `15/35` | Load by email, enforce account/lock/password policy, issue rotated tokens + session/client profile and audit |
| AUTH-TOKEN-REFRESH | Public | `30/30` | Validate current refresh token, rotate session once, blacklist old access JTI |
| AUTH-LOGOUT | Bearer | global | Blacklist current JTI fail-closed and durably revoke its session |
| AUTH-LOGOUT-ALL | Bearer | global | Invalidate all sessions/auth state |
| AUTH-PASSWORD-FORGOT | Public | `10/20` | Non-enumerating response; create hashed reset token and mail link |
| AUTH-PASSWORD-RESET | Public | `10/20` | Atomically consume token, update credential/state and invalidate auth |
| AUTH-PASSWORD-CHANGE | Bearer | `10/20` | Verify current password, update credential and invalidate auth |
| AUTH-PASSWORD-FORCE-CHANGE | Public compatibility flow | `10/20` | Verify email + current password and require `password_change_required` |

## Ordering and collision rules

- Format validation precedes rate limit and database/bcrypt work.
- Frozen bearer routes preserve the unauthenticated `401` boundary before body
  validation. Once authenticated, format validation still precedes their sensitive
  bucket and domain work.
- Login and force-change return `INVALID_CREDENTIALS` for an unknown account or a
  wrong credential regardless of hidden account state. A state-specific error is
  returned only after the credential proof succeeds. Verification does not reveal
  whether an address is already verified; resend and forgot keep generic success.
- Quy tắc vòng đời session, xoay vòng refresh token, khóa đồng thời (single-winner lock), phát hiện tái sử dụng (reuse detection) và thu hồi phiên tuân thủ chuẩn hóa tại [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md).
- Login locks the user row before changing failed attempts, lock state or last-login state.
- Successful login must re-check user/auth version after expensive credential/MFA work before issuing a session.
- Verification/resend for the same subject serialize; only one active or consumed challenge wins.
- Refresh locks the session row; concurrent refresh có đúng một winner và reuse invalidates toàn bộ auth state theo [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md#2-xoay-vòng-phiên--kiểm-soát-đồng-thời-session-rotation--concurrency).
- Credential/reset mutation, audit and outbox enqueue commit in one MySQL transaction.
- Reset token mang `auth_version` snapshot; account row luôn khóa trước reset-token row. Credential snapshot đổi trong lúc bcrypt chạy làm request cũ thất bại thay vì ghi đè password mới.
- Password mutation vô hiệu reset token, email-change workflow và sessions trong cùng MySQL transaction; không còn Redis email-change cleanup path.
- Redis blacklist/fast marker is outside MySQL transaction with explicit fail-closed/compensation semantics.

## Current implementation

- Registration, email verification and resend use request-scoped `verification_challenges`; migration 034 removed the drained `otp_codes` table.
- Login, refresh and logout use the `auth` and `session` modules. Login rechecks the bcrypt credential snapshot under the locked canonical account row before attempts/session writes.
- Logout-all now increments durable `auth_version` and deletes MySQL sessions in one transaction.
- Verification OTP, password-reset, email-change and admin notification payloads
  are encrypted in the durable outbox, delivered by the bounded worker and redacted
  after delivery.
- Admin reset uses a one-time reset link. Force-change remains as a frozen public compatibility operation for accounts explicitly marked `password_change_required`.
