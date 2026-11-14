# MySQL Schema Design

Migration 034 là schema head hiện tại. Toàn bộ cấu trúc cột vật lý và ràng buộc chi tiết của 16 bảng được chuẩn hóa duy nhất tại [current-schema.md](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/data/current-schema.md). Tài liệu này tập trung vào lý do thiết kế kiến trúc và phân định trách nhiệm giữa các aggregate.

## Aggregate Ownership

| Aggregate | Bảng sở hữu | Trách nhiệm kiến trúc |
| --- | --- | --- |
| Account identity & security | `users` | Canonical identity, credentials, lifecycle và trạng thái bảo mật cốt lõi (`auth_version`) |
| Profile & presentation | `user_profiles` | Thông tin hiển thị cá nhân, liên hệ và avatar object key |
| Access control | `roles`, `permissions`, `user_roles`, `role_permissions` | RBAC phân quyền hệ thống và gán vai trò |
| Session & rotation history | `sessions`, `refresh_token_history`, `devices` | Quản lý phiên hoạt động, lịch sử xoay vòng phát hiện tấn công reuse, và client profile |
| Verification workflows | `verification_challenges`, `email_change_requests`, `password_reset_tokens` | Luồng xác thực đăng ký, đổi email hai pha, và đặt lại mật khẩu an toàn |
| Multi-Factor Authentication | `user_totp`, `user_totp_recovery_codes` | Lưu trữ bí mật TOTP mã hóa AES-GCM và mã khôi phục một lần (hash) |
| Delivery & audit | `outbox_events`, `audit_logs` | Hàng đợi sự kiện bền vững (Transactional Outbox) và nhật ký kiểm toán bất biến |

## Lý do thiết kế kiến trúc

### 1. Phân tách `users` và `user_profiles`
- **Tách rời Security Invariant và Profile Data**: Bảng `users` chỉ lưu trữ thông tin nhận diện cốt lõi (email, username, password hash) và các trạng thái bảo mật nhạy cảm (`auth_version`, khóa tài khoản, đếm số lần thất bại). Bảng `user_profiles` chịu trách nhiệm về thông tin hiển thị (họ tên, số điện thoại, ngày sinh, avatar key).
- **Giảm thiểu Lock Contention**: Các thao tác cập nhật profile thông thường không gây tranh chấp hàng (row lock) với luồng xác thực, xoay phiên hoặc kiểm tra trạng thái bảo mật của tài khoản.
- **Bảo mật và Phân quyền**: Ngăn chặn rủi ro vô tình ghi đè hoặc làm rò rỉ trường bảo mật trong các câu lệnh truy vấn/cập nhật thông tin người dùng công khai.

### 2. Phân tách `sessions` và `refresh_token_history`
- **Single Responsibility cho phiên hoạt động**: Bảng `sessions` chỉ duy trì các phiên đang hoạt động hoặc vừa bị thu hồi, với cặp khóa `access_jti` và `current_refresh_hash` duy nhất.
- **Phát hiện tái sử dụng Refresh Token (Reuse Detection)**: `refresh_token_history` hoạt động như một append-only audit trail lưu trữ các token hash đã từng được xoay vòng. Khi một token cũ bị kẻ gian sử dụng lại, hệ thống đối chiếu lịch sử để phát hiện hành vi xâm phạm và lập tức thu hồi toàn bộ phiên của tài khoản.
- **Tối ưu hiệu năng**: Bảng `sessions` duy trì kích thước nhỏ gọn theo số lượng phiên hoạt động thực tế, giúp các truy vấn kiểm tra phiên, xác thực và thu hồi đạt hiệu năng cao nhất mà không bị phình to bởi lịch sử xoay vòng token.

### 3. Hàng đợi sự kiện bền vững (`outbox_events`)
- **Đảm bảo tính nhất quán (Transactional Outbox Pattern)**: Thay đổi nghiệp vụ (như đăng ký, yêu cầu đổi email, cấp lại mật khẩu) và sự kiện gửi thông báo (email) được ghi vào cùng một database transaction. Tránh hoàn toàn tình trạng mất mát thông báo nếu hệ thống gặp sự cố sau khi commit dữ liệu.
- **Cô lập Network I/O khỏi Database Transaction**: Tuyệt đối không gọi dịch vụ mạng bên thứ ba (SMTP, Resend API) trong database transaction để tránh giữ khóa hàng quá lâu và gây cạn kiệt connection pool.
- **Phân phối tin cậy**: Bounded background worker định kỳ quét sự kiện từ outbox, xử lý với cơ chế exponential backoff, dead-letter queue, idempotency key chống trùng lặp và xóa/redact payload nhạy cảm sau khi hoàn tất.

### 4. Quy tắc bảo mật cho Workflow và RBAC
- **Verification Challenges theo Request Scope**: Thay thế bảng OTP dùng chung trước đây bằng `verification_challenges` có scope rõ ràng theo từng request, gắn hash bí mật, thời hạn hết hạn và số lần thử tối đa.
- **Đổi email hai pha (`email_change_requests`)**: Lưu trữ trạng thái bền vững trong MySQL, yêu cầu xác thực đồng thời từ cả email cũ và email mới để ngăn chặn chiếm đoạt tài khoản.
- **RBAC và Last-Admin Invariant**: Toàn bộ thao tác thay đổi vai trò hoặc trạng thái quản trị viên bắt buộc tuân thủ quy tắc bảo vệ usable admin cuối cùng và tăng `auth_version` để thu hồi phiên cũ ngay trong transaction.

Cấu trúc schema chi tiết cho toàn bộ 16 bảng vật lý: xem [current-schema.md](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/data/current-schema.md).
