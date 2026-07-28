# Security Boundaries

## Request order

Với input hợp lệ, thứ tự chuẩn là:

```text
format validation → rate limit → authentication/authorization
→ locked DB read → bcrypt/crypto → transactional write
```

Không tính failed attempt hoặc per-use-case rate limit cho input sai format.

## Boundary rules

- Auth, JTI blacklist, MFA challenge và rate limit fail-closed khi Redis không xác định được kết quả.
- Business error dùng `apperror`; system error wrap nguyên nhân bằng `%w`.
- SQL dùng parameter binding; mutation nhiều bước dùng `TxManager`.
- Record được sửa phải `FOR UPDATE` hoặc atomic conditional update.
- Call trong transaction dùng `txCtx`; external system nằm ngoài transaction.
- Password, OTP, reset token, refresh token, TOTP secret/recovery code không được log plaintext.
- Password/email/role/lock/MFA mutation làm mất hiệu lực auth state.
- Mọi secret mail payload được mã hóa trong durable outbox và chỉ được gửi bởi bounded worker.
- CORS không được phản chiếu origin tùy ý khi credentials bật.
- `TRUSTED_PROXIES` rỗng nghĩa là không tin forwarded client IP.

## Current platform boundary

- Global token bucket runs before body parsing as a coarse DoS boundary.
- Sensitive public use-case buckets run only after JSON format/byte validation.
  Protected routes preserve the frozen unauthenticated `401` boundary, then validate
  input before their sensitive bucket and domain work.
- Limiter decision, violation count and temporary ban are one Redis Lua operation;
  Redis errors fail closed.
- Liveness/readiness never depend on rate-limit or IP-ban state.
- MySQL TLS mode and connection pools are validated at startup. Production requires
  verified TLS unless an explicit emergency override is active.

HTTP transport, validation, middleware và response mapping cùng thuộc
`internal/httpapi`; business transition không nằm ở boundary này.
