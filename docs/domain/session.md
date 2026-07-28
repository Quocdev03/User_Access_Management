# Session Domain

## Current

MySQL lưu session, durable refresh history và `auth_version`. Redis chỉ giữ JTI blacklist, refresh-reuse fast marker và TTL state. Middleware so JWT `auth_version` với canonical account state trong MySQL; `user_revoked_epoch` không còn runtime owner. Session list/revoke, rotation, issuance và client-profile behavior thuộc `internal/session`.

## Canonical storage

```text
sessions
├── current_refresh_hash
├── access_jti NOT NULL
├── client_profile_id
├── expires_at
└── revoked_at

refresh_token_history
├── token_hash UNIQUE
├── session_id
├── user_id
├── rotated_at
└── expires_at
```

- MySQL là durable source cho session và refresh history.
- Redis JTI chỉ tối ưu thu hồi access token theo TTL.
- `auth_version` đã thay `user_revoked_epoch`; correctness-first middleware đọc MySQL.
- Rotation lock session row, lưu old refresh hash vào history rồi cập nhật current hash. Expired-session cleanup commit trước khi trả business error.
- Reuse detection vẫn hoạt động sau Redis restart.
- Session cap revoke session cũ nhất và blacklist JTI trước khi trả login thành công.
- `devices` được diễn giải là observed client profile; migration 029 bỏ uniqueness theo OS/browser vì hai family không định danh physical device.
- Migration 034 đã xóa bốn session projection cũ; issuance, rotation, list và revoke chỉ dùng `current_refresh_hash`, `access_jti` và `client_profile_id`.
