# Account Use Cases

All operations require bearer access and global rate limiting.

## Profile

| ID | Path | Behavior |
| --- | --- | --- |
| ACCOUNT-PROFILE-GET | `GET /users/me` | Return current identity/profile, roles and effective public status |
| ACCOUNT-PROFILE-UPDATE | `PATCH /users/me` | Validate provided profile fields, update only mutable profile data and append audit |

Profile GET/UPDATE gọi trực tiếp `internal/account.Profile` và chỉ đọc/ghi
`user_profiles`. Partial update dùng atomic per-field update để concurrent request
sửa các field khác nhau không lost update; không transition account security state.

## Email change

The three email operations share a one-minute token bucket with capacity 5; 15
rejected valid requests trigger the configured temporary ban.

> [!NOTE]
> **Công thức cấu hình Rate Limit giữa Code và Docs**:
> Theo tài liệu, các tác vụ đổi email và upload avatar có capacity là 5 và abuse threshold là 15 (sau 15 lần vi phạm liên tiếp sẽ kích hoạt ban). Mã nguồn Go (`internal/httpapi/*_routes.go`) sử dụng công thức:
> `banLimit (code) = capacity + abuseThreshold (docs) = 5 + 15 = 20`
> tương ứng với tham số `(5, 20)` truyền vào middleware rate limit.

| ID | Path | Behavior |
| --- | --- | --- |
| ACCOUNT-EMAIL-CHANGE-REQUEST | `POST /users/me/email/change-request` | Check new email uniqueness, create old/new verification state and notify both addresses |
| ACCOUNT-EMAIL-CHANGE-VERIFY | `POST /users/me/email/verify` | Require both proofs for the same request/account snapshot, update email and invalidate auth |
| ACCOUNT-EMAIL-CHANGE-RESEND | `POST /users/me/email/resend` | Require live pending request and replace its challenges |

These routes now call `internal/account.Email` directly. Transaction/lock order is user row → email-change request → old challenge → new challenge. Request, resend replacement, challenges, audit and outbox are durable MySQL data; Redis has no email-change owner.

- Request depends on the canonical account, current-password proof, request/challenge stores, encrypted mail outbox and audit. It rechecks the credential/auth-version snapshot under the account lock.
- Resend cancels the previous request and its pending deliveries, then creates one replacement request with exactly two active challenges.
- Verify commits failed-attempt counters, consumes both proofs, updates email, increments `auth_version`, deletes sessions, invalidates password-reset work and appends audit/outbox in one transaction.
- Concurrent verify has one winner. Admin email or password mutation cancels request/challenges and relevant reset delivery in its own mutation transaction. Expired or stale requests fail without changing the account.

## Avatar

| ID | Path | Rate | Behavior |
| --- | --- | --- | --- |
| ACCOUNT-AVATAR-UPLOAD | `POST /users/me/avatar` | capacity 5; ban after 15 rejects | Accept JPEG/PNG/WebP up to 2 MiB; validate extension and detected content type |
| ACCOUNT-AVATAR-DELETE | `DELETE /users/me/avatar` | global | Clear avatar reference and remove object when safe |

These routes now call `internal/account.Avatar`. The application validates the 2 MiB limit, extension allowlist, detected content type and extension/content match before writing. It generates the object key; client filenames never become storage paths.

The blob is written before the MySQL transaction. The transaction swaps
`user_profiles.avatar_object_key` and appends audit. A failed transaction deletes
the new blob best-effort; after commit, replacement/delete removes the old blob
best-effort and logs cleanup failure without rolling back the new profile state.

`internal/blob.LocalStore` maps object keys under `./uploads` and serves `/uploads/*`
only outside production. Production uses the S3-compatible adapter and returns URLs
under `S3_PUBLIC_BASE_URL`. The one-off avatar migrator preserves external URLs,
normalizes owned `/uploads/...` keys and commits only after SHA-256 verification.

## Session consequence

Profile/avatar-only changes do not revoke auth. Verified email change increments `auth_version` and invalidates all sessions. Mail side effects are outbox events and do not widen the MySQL transaction.
