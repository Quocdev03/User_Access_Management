# Access Control Domain

## Authorization model

- Admin routes yêu cầu authenticated user có durable permission tương ứng trong MySQL.
- System role `admin` bypass permission lookup; mọi role khác, kể cả custom role, được authorize theo permission thay vì hard-coded role gate.
- Lỗi load role/permission là lỗi hệ thống; không cấp role mặc định.
- Permission có semantic `{resource}.{action}`.

## System roles and last-admin invariant

`admin`, `moderator`, `user` là system roles, được đánh dấu bằng `roles.is_system`; runtime không suy ra quyền bảo vệ chỉ từ tên.

Mutation có thể làm mất usable admin cuối cùng phải:

1. Lock system admin role row.
2. Lock target account rồi target assignment rows theo thứ tự ổn định.
3. Lock toàn bộ admin assignment rows rồi canonical account-state rows theo user ID tăng dần.
4. Đếm usable admins trong cùng transaction và reject nếu kết quả bằng 0.

Usable admin là user có lifecycle active, verified, không admin-locked và có role admin.

## Session consequence

Role assign/remove, admin lock/disable, identity hoặc credential mutation tăng `auth_version` trong cùng transaction. Không chỉ xóa Redis sau commit rồi coi mutation đã hoàn tất.
