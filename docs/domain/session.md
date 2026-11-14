# Session Domain

Tài liệu này là source of truth duy nhất cho toàn bộ các quy tắc vòng đời phiên (session lifecycle), cơ chế xoay vòng token, kiểm soát giới hạn phiên, phát hiện tái sử dụng và thu hồi phiên trong hệ thống.

## Kiến trúc lưu trữ (Canonical Storage)

MySQL là nguồn lưu trữ bền vững (durable source of truth) cho thông tin phiên, lịch sử xoay vòng refresh token và phiên bản xác thực `auth_version`. Redis đóng vai trò lưu trữ TTL state để tối ưu hóa kiểm tra nhanh (blacklist JTI và marker phát hiện reuse nhanh).

```text
sessions
├── id PK
├── user_id FK(users.id)
├── access_jti NOT NULL
├── current_refresh_hash NOT NULL UNIQUE
├── ip_address
├── user_agent
├── client_profile_id FK(devices.id)
├── expires_at NOT NULL
├── revoked_at
├── created_at
└── updated_at

refresh_token_history
├── id PK
├── token_hash NOT NULL UNIQUE
├── session_id FK(sessions.id)
├── user_id FK(users.id)
├── rotated_at NOT NULL
└── expires_at NOT NULL
```

## Các quy tắc vòng đời phiên (Session Lifecycle Invariants)

### 1. Khởi tạo phiên & Giới hạn phiên (Session Issuance & Session Cap)
- Khi người dùng đăng nhập thành công (hoặc hoàn tất xác thực MFA), hệ thống kiểm tra số lượng phiên đang hoạt động của người dùng.
- **Session Cap Enforcement**: Nếu số lượng phiên vượt quá cấu hình `MAX_SESSIONS_PER_USER` (mặc định 10), phiên cũ nhất sẽ bị thu hồi bền vững trong MySQL và access token JTI tương ứng bị đưa vào blacklist fail-closed trước khi trả về phiên mới.
- Phiên mới luôn ghi nhận cặp `access_jti` (duy nhất, NOT NULL), `current_refresh_hash` (duy nhất, NOT NULL) cùng liên kết `client_profile_id` quan sát được.

### 2. Xoay vòng phiên & Kiểm soát đồng thời (Session Rotation & Concurrency)
- **Khóa hàng phiên (Row-level Locking)**: Mọi thao tác refresh token đều thực hiện khóa hàng phiên trong MySQL (`FOR UPDATE`) để ngăn chặn race condition giữa các request đồng thời.
- **Quy tắc Single Winner**: Chỉ request đầu tiên mang đúng `current_refresh_hash` hiện hành của phiên mới được phép xoay vòng thành công. Mọi request refresh đồng thời khác sẽ thất bại.
- **Ghi nhận lịch sử xoay vòng**: Hash refresh token cũ được lưu ngay vào `refresh_token_history` (kèm `rotated_at`), sau đó phiên được cập nhật `current_refresh_hash` và `access_jti` mới.
- **Xử lý phiên hết hạn**: Nếu phát hiện phiên đã quá hạn `expires_at`, hệ thống commit việc thu hồi phiên trong database trước khi trả lỗi nghiệp vụ `ErrSessionExpired`.

### 3. Phát hiện tái sử dụng Token (Reuse Detection)
- Khi một refresh token được gửi lên nhưng hash của nó đã tồn tại trong `refresh_token_history` (tức token cũ đã từng được xoay vòng):
  - Hệ thống xác định đây là hành vi tấn công tái sử dụng (token reuse attack).
  - Lập tức kích hoạt cơ chế thu hồi toàn bộ phiên của tài khoản (tăng `auth_version` và xóa/thu hồi mọi phiên đang hoạt động) để bảo vệ người dùng.
- `refresh_token_history` trong MySQL là durable source đảm bảo việc phát hiện reuse vẫn chính xác tuyệt đối ngay cả khi Redis gặp sự cố hoặc khởi động lại. Redis chỉ giữ marker có TTL để fast-check.

### 4. Thu hồi phiên (Session Revocation)
- **Thu hồi một phiên (`SESSION-REVOKE`, `AUTH-LOGOUT`)**:
  - Yêu cầu xác minh quyền sở hữu phiên của người dùng đăng nhập.
  - Cập nhật thời điểm `revoked_at` trong MySQL, đồng thời đưa `access_jti` vào Redis blacklist với TTL bằng thời gian sống còn lại của access token.
  - **Fail-Closed**: Nếu Redis gặp sự cố khi ghi blacklist JTI, hệ thống kích hoạt compensation thu hồi bền vững toàn bộ phiên của tài khoản và trả lỗi 503 để bảo đảm an toàn.
- **Thu hồi toàn cầu (Global Revocation / Logout All)**:
  - Khi người dùng thực hiện logout-all, đổi mật khẩu, đổi email, bị admin khóa tài khoản hoặc thay đổi vai trò:
  - Hệ thống tăng giá trị `auth_version` của tài khoản trong MySQL và thu hồi toàn bộ sessions trong cùng một database transaction.
  - JWT middleware đối chiếu trực tiếp `auth_version` từ JWT claims với `auth_version` trong MySQL (fail-closed), đảm bảo vô hiệu hóa ngay lập tức mọi token đã cấp mà không phụ thuộc vào trạng thái cache.

### 5. Client Profile (`devices`)
- Bảng `devices` lưu vết các profile client quan sát được trong quá trình đăng nhập (gồm toàn bộ user-agent, họ hệ điều hành, họ trình duyệt và địa chỉ IP gần nhất).
- Không áp dụng ràng buộc duy nhất theo `(user_id, os, browser)` vì hai trường này không định danh được thiết bị vật lý thực tế. Endpoint `/users/me/devices` được giữ để tương thích ngược.
