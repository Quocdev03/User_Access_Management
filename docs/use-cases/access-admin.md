# Access and Admin Use Cases

Every route requires bearer auth, the listed durable permission and global rate limiting.
System role `admin` bypasses permission lookup; custom roles work without a hard-coded
`admin|moderator` group gate. Database errors fail authorization.

## User administration

| ID | Path | Permission | Contract |
| --- | --- | --- | --- |
| ACCESS-USER-LIST | `GET /admin/users` | `users.read` | Paginate (default 20, max 100), filter and whitelist sort; batch-load roles |
| ACCESS-USER-GET | `GET /admin/users/{id}` | `users.read` | Return user detail and roles |
| ACCESS-USER-UPDATE | `PUT /admin/users/{id}` | `users.update` | Locked mutation of allowed identity/profile fields; email uniqueness and verification rules |
| ACCESS-USER-STATUS-CHANGE | `PATCH /admin/users/{id}/status` | `users.lock` | Change active/inactive/locked state with self/target/last-admin guards |
| ACCESS-USER-PASSWORD-RESET | `POST /admin/users/{id}/password/reset` | `users.reset_password` | Revoke current sessions and enqueue an encrypted one-time reset link; never create or mail a temporary password |
| ACCESS-USER-NOTIFY | `POST /admin/users/{id}/notify` | `users.notify` | Notify active target; escape subject/message and append audit |

Actor without durable admin role cannot mutate an admin target. An admin cannot disable/lock/remove the final usable admin. Status/identity/password changes increment target auth version transactionally.

## Role administration

| ID | Path | Permission | Contract |
| --- | --- | --- | --- |
| ACCESS-ROLE-LIST | `GET /admin/roles` | `roles.read` | List roles and permission data |
| ACCESS-ROLE-CREATE | `POST /admin/roles` | `roles.create` | Reject duplicate/reserved system names |
| ACCESS-ROLE-UPDATE | `PUT /admin/roles/{id}` | `roles.update` | Do not rename system roles |
| ACCESS-ROLE-DELETE | `DELETE /admin/roles/{id}` | `roles.delete` | Reject system or assigned role |
| ACCESS-ROLE-PERMISSIONS-REPLACE | `PUT /admin/roles/{id}/permissions` | `permissions.assign` | Validate every permission ID and replace set in one transaction |
| ACCESS-ROLE-ASSIGN | `POST /admin/users/{id}/roles` | `roles.assign` | Validate role; assigning admin requires admin actor |
| ACCESS-ROLE-REMOVE | `DELETE /admin/users/{id}/roles/{roleId}` | `roles.assign` | Removing admin requires admin actor and last-admin guard |

Role assignment/removal locks in deterministic order, appends audit and increments target user's auth version in the same transaction.

Replacing a role's permission set accepts an explicit empty array to clear the set. A
missing `permission_ids` field is invalid. A permission/name change invalidates affected
users in the same transaction; store errors are never treated as an empty permission set.

## Audit export

| ID | Path | Permission | Contract |
| --- | --- | --- | --- |
| AUDIT-EXPORT | `GET /admin/audit-logs/export` | `audit_logs.export` | UTF-8 BOM CSV, maximum 10,000 rows; filters user/action/start/end |

Dates use `YYYY-MM-DD`; end date is inclusive by querying `< end + 1 day`. Export does not mutate audit data.

## System health

- `GET /health`: liveness, no backing-service dependency.
- `GET /health/ready`: performs direct bounded MySQL and Redis pings and returns 503 on dependency failure.
