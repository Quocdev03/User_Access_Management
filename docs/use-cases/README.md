# Use Cases

Public paths are relative to `/api/v1`. Current contract baseline has 41 Swagger
operations. Đây là tập phải giữ tương thích; operation mới phải có semantic owner,
contract test và generated OpenAPI trong cùng thay đổi.

## Route coverage

| # | Semantic ID | Method and path | Owner |
| ---: | --- | --- | --- |
| 1 | AUTH-REGISTER | `POST /auth/register` | [authentication](authentication.md) |
| 2 | AUTH-EMAIL-VERIFY | `POST /auth/email/verify` | [authentication](authentication.md) |
| 3 | AUTH-EMAIL-RESEND | `POST /auth/email/resend` | [authentication](authentication.md) |
| 4 | AUTH-LOGIN | `POST /auth/login` | [authentication](authentication.md) |
| 5 | AUTH-TOKEN-REFRESH | `POST /auth/token/refresh` | [authentication](authentication.md) |
| 6 | AUTH-LOGOUT | `POST /auth/logout` | [authentication](authentication.md) |
| 7 | AUTH-LOGOUT-ALL | `POST /auth/logout-all` | [authentication](authentication.md) |
| 8 | AUTH-PASSWORD-FORGOT | `POST /auth/password/forgot` | [authentication](authentication.md) |
| 9 | AUTH-PASSWORD-RESET | `POST /auth/password/reset` | [authentication](authentication.md) |
| 10 | AUTH-PASSWORD-CHANGE | `POST /auth/password/change` | [authentication](authentication.md) |
| 11 | AUTH-PASSWORD-FORCE-CHANGE | `POST /auth/password/force-change` | [authentication](authentication.md) |
| 12 | MFA-LOGIN-VERIFY | `POST /auth/mfa/login/verify` | [MFA](mfa.md) |
| 13 | MFA-SETUP | `POST /auth/mfa/setup` | [MFA](mfa.md) |
| 14 | MFA-CONFIRM | `POST /auth/mfa/confirm` | [MFA](mfa.md) |
| 15 | MFA-DISABLE | `POST /auth/mfa/disable` | [MFA](mfa.md) |
| 16 | MFA-STATUS | `GET /auth/mfa/status` | [MFA](mfa.md) |
| 17 | MFA-RECOVERY-REGENERATE | `POST /auth/mfa/recovery/regenerate` | [MFA](mfa.md) |
| 18 | ACCOUNT-PROFILE-GET | `GET /users/me` | [account](account.md) |
| 19 | ACCOUNT-PROFILE-UPDATE | `PATCH /users/me` | [account](account.md) |
| 20 | ACCOUNT-EMAIL-CHANGE-REQUEST | `POST /users/me/email/change-request` | [account](account.md) |
| 21 | ACCOUNT-EMAIL-CHANGE-VERIFY | `POST /users/me/email/verify` | [account](account.md) |
| 22 | ACCOUNT-EMAIL-CHANGE-RESEND | `POST /users/me/email/resend` | [account](account.md) |
| 23 | ACCOUNT-AVATAR-UPLOAD | `POST /users/me/avatar` | [account](account.md) |
| 24 | ACCOUNT-AVATAR-DELETE | `DELETE /users/me/avatar` | [account](account.md) |
| 25 | SESSION-LIST | `GET /users/me/sessions` | [session](session.md) |
| 26 | SESSION-REVOKE | `DELETE /users/me/sessions/{id}` | [session](session.md) |
| 27 | CLIENT-PROFILE-LIST | `GET /users/me/devices` | [session](session.md) |
| 28 | ACCESS-USER-LIST | `GET /admin/users` | [access/admin](access-admin.md) |
| 29 | ACCESS-USER-GET | `GET /admin/users/{id}` | [access/admin](access-admin.md) |
| 30 | ACCESS-USER-UPDATE | `PUT /admin/users/{id}` | [access/admin](access-admin.md) |
| 31 | ACCESS-USER-STATUS-CHANGE | `PATCH /admin/users/{id}/status` | [access/admin](access-admin.md) |
| 32 | ACCESS-USER-PASSWORD-RESET | `POST /admin/users/{id}/password/reset` | [access/admin](access-admin.md) |
| 33 | ACCESS-USER-NOTIFY | `POST /admin/users/{id}/notify` | [access/admin](access-admin.md) |
| 34 | ACCESS-ROLE-LIST | `GET /admin/roles` | [access/admin](access-admin.md) |
| 35 | ACCESS-ROLE-CREATE | `POST /admin/roles` | [access/admin](access-admin.md) |
| 36 | ACCESS-ROLE-UPDATE | `PUT /admin/roles/{id}` | [access/admin](access-admin.md) |
| 37 | ACCESS-ROLE-DELETE | `DELETE /admin/roles/{id}` | [access/admin](access-admin.md) |
| 38 | ACCESS-ROLE-PERMISSIONS-REPLACE | `PUT /admin/roles/{id}/permissions` | [access/admin](access-admin.md) |
| 39 | ACCESS-ROLE-ASSIGN | `POST /admin/users/{id}/roles` | [access/admin](access-admin.md) |
| 40 | ACCESS-ROLE-REMOVE | `DELETE /admin/users/{id}/roles/{roleId}` | [access/admin](access-admin.md) |
| 41 | AUDIT-EXPORT | `GET /admin/audit-logs/export` | [access/admin](access-admin.md) |

Outside Swagger operations: `SYSTEM-LIVENESS GET /health` and `SYSTEM-READINESS GET /health/ready`.

## Journey graph

```text
AUTH-REGISTER → AUTH-EMAIL-VERIFY → AUTH-LOGIN
→ MFA-LOGIN-VERIFY when enabled → SessionIssuer
```

```text
AUTH-PASSWORD-FORGOT → AUTH-PASSWORD-RESET
→ AuthInvalidator → AUTH-LOGIN
```

```text
ACCOUNT-EMAIL-CHANGE-REQUEST
→ optional ACCOUNT-EMAIL-CHANGE-RESEND
→ ACCOUNT-EMAIL-CHANGE-VERIFY → AuthInvalidator
```

```text
ACCESS-ROLE-ASSIGN / ACCESS-ROLE-REMOVE
→ LastAdminGuard → role mutation → AuthInvalidator
```

New documents and code use these semantic IDs; numeric use-case identifiers are retired.
