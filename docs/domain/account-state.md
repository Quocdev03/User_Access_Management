# Account State

## Current canonical model

`internal/accountstate/` là owner duy nhất của policy và transition. Typed store trong
`internal/mysqlstore/` chỉ đọc/ghi các cột canonical; migration 033 đã xóa state/profile
mirror cũ sau consistency gate và replica drain.

```text
lifecycle_state: pending_verification | active | disabled
email_verified
administrative_locked_at
login_locked_until
failed_login_attempts
password_change_required
auth_version
```

Effective public status vẫn tương thích:

```text
administrative_locked_at != NULL → locked
login_locked_until > now         → locked
lifecycle_state != active        → inactive
otherwise                        → active
```

`accountstate` là owner duy nhất của effective status và transition.

## State consequences

| Event | Required result |
| --- | --- |
| Verify email | lifecycle chuyển active nếu không có admin restriction |
| Admin disable/lock | tăng `auth_version`, không tự mở bằng password flow |
| Brute-force expiry | chỉ mở login lock, không xóa admin lock |
| Password/email/role/MFA change | tăng `auth_version` trong transaction |
| Profile-only update | không khóa security row và không tăng `auth_version` |
| Force-change hoàn tất | clear `password_change_required` |

Transition cần audit được append trong cùng MySQL transaction; mail được enqueue qua outbox.
