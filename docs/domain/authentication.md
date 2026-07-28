# Authentication Domain

## Invariants

- Email là login identifier hiện tại.
- Password hash dùng bcrypt; raw password chỉ tồn tại trong request scope.
- Email verification OTP lưu hash `SHA256(otp + pepper)`.
- Forgot-password dùng opaque reset token hash, không dùng OTP legacy type.
- Token/session chỉ được cấp sau khi credential, account state và MFA (nếu bật) đều hợp lệ.
- Refresh rotation là one-time; reuse làm mất hiệu lực toàn bộ auth state của user.
- Security mutation tăng durable `auth_version`; middleware so claim với MySQL.
- Login chỉ cấp session nếu password-hash snapshot sau bcrypt vẫn khớp account row đã khóa; credential đổi đồng thời làm request cũ thất bại.
- Password-reset token gắn `auth_version` tại lúc issue, chỉ consume một lần và không thể ghi đè credential đã đổi sau khi token được phát hành.
- Change/force-change recheck password-hash snapshot dưới account row lock; mọi credential mutation tăng `auth_version`, xóa sessions và vô hiệu security workflow liên quan trong cùng transaction.

## Verification workflow

Registration verification và email change đều dùng `verification_challenges` request-scoped và durable. Email change có aggregate `email_change_requests`, hai proof cũ/mới và account auth-version snapshot. Challenge issuer/consumer kiểm soát attempts, expiry và consumed state trong MySQL transaction; wrong-attempt state commit trước khi trả business error. Redis không giữ business state của workflow này.

Verification OTP được mã hóa trong outbox payload, gửi bởi bounded worker và redacted sau delivery. OTP plaintext không được log hoặc lưu trực tiếp trong challenge/outbox.

Password-reset token plaintext cũng chỉ tồn tại trong request/outbox delivery scope. Database lưu SHA-256 token; outbox lưu payload AES-GCM và redacted sau khi giao hoặc bị supersede.

## MFA

- TOTP theo RFC 6238, secret mã hóa AES-GCM với key version.
- Setup chưa có hiệu lực cho tới confirm.
- Login khi MFA bật chỉ trả challenge; chưa cấp JWT/session.
- Challenge Redis gồm user ID, auth version, attempts và TTL.
- Claim/finish/release challenge là các Redis Lua operation nguyên tử; không dùng
  `GET` rồi `DEL`. Chỉ claimant mới được hoàn tất challenge.
- Sau khi claim, use case recheck account, `auth_version` và MFA dưới row lock trước
  khi tạo session.
- TOTP step và recovery code đều one-time bằng conditional MySQL update.
- Confirm/disable/regenerate tăng `auth_version` và xóa sessions trong cùng
  transaction với MFA mutation.
- Disable/regenerate yêu cầu current password cộng TOTP hoặc recovery code.
