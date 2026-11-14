# Session Use Cases

All operations require bearer access and global rate limiting. Quy tắc toàn diện về vòng đời phiên, giới hạn phiên (session cap), xoay vòng token, kiểm soát đồng thời và thu hồi phiên được quy định chuẩn hóa tại [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md).

| ID | Method and path | Contract |
| --- | --- | --- |
| SESSION-LIST | `GET /users/me/sessions` | List unexpired owned sessions; mark the current session by access-token JTI |
| SESSION-REVOKE | `DELETE /users/me/sessions/{id}` | Require ownership, blacklist target JTI fail-closed and revoke/delete the session |
| CLIENT-PROFILE-LIST | `GET /users/me/devices` | List observed client profiles recorded during login |

## Collision and failure rules

- Session ID lookup được giới hạn nghiêm ngặt theo authenticated user; revoke có tính idempotent sau khi xác thực quyền sở hữu và không làm lộ phiên của người dùng khác.
- `SESSION-REVOKE`: Ghi nhận `revoked_at` bền vững và blacklist JTI fail-closed; nếu Redis lỗi sẽ áp dụng compensation invalidate-all theo [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md#4-thu-hồi-phiên-session-revocation).
- Xử lý đồng thời giữa refresh và revoke: Tuân thủ quy tắc khóa hàng phiên và single-winner theo [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md#2-xoay-vòng-phiên--kiểm-soát-đồng-thời-session-rotation--concurrency).
- Giới hạn phiên (`MAX_SESSIONS_PER_USER`) và client profile: Áp dụng cơ chế thu hồi phiên cũ nhất và lưu vết client theo [session domain](file:///c:/Users/ccquo/Downloads/Compressed/user_access_management/docs/domain/session.md#1-khởi-tạo-phiên--giới-hạn-phiên-session-issuance--session-cap).
