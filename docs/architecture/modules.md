# Modules

## Current implementation

Public HTTP transport và toàn bộ auth/account/session/admin use case đã có owner đích:

```text
httpapi → auth | account | session | access → mysqlstore/redisstore/mail/blob
```

Các package global theo layer cũ không còn production owner. `cmd/server` chỉ sở hữu
HTTP lifecycle và dependency wiring; migration ở `cmd/migrate`, còn outbox và cleanup
ở `cmd/worker`.

## Module ownership

```text
cmd/
├── server/
├── worker/
├── migrate/
├── avatar-migrate/
└── bootstrap-admin/

internal/
├── httpapi/
├── auth/
├── account/
├── session/
├── access/
├── accountstate/
├── mysqlstore/
├── redisstore/
├── mail/
├── blob/
└── jobs/
```

| Package | Owner |
| --- | --- |
| `httpapi` | Router, middleware composition, bind/validate, handler, response mapping, Swagger annotations |
| `auth` | Register, email verification, login, refresh, password và MFA |
| `account` | Profile, email change, avatar |
| `session` | Issue, rotate, revoke, list session và observed client profile |
| `access` | RBAC, admin user/role mutation, last-admin guard |
| `accountstate` | Pure transition policy và effective public status |
| `mysqlstore` | MySQL query/command; không gọi Redis/mail/blob |
| `redisstore` | TTL state và atomic Redis operation |
| `mail`, `blob` | Runtime adapters; interface chỉ tại boundary có nhiều implementation |
| `jobs` | Outbox delivery, cleanup, scheduled maintenance |

## Dependency rules

```text
HTTP adapter → application use case → domain policy → infrastructure adapter
```

- Domain không import `httpapi`.
- Store không gọi chéo nhau.
- Application use case sở hữu transaction.
- Không gọi Redis, mail hoặc blob trong MySQL transaction.
- Shared account transition nằm ở `accountstate`; shared session capability nằm ở `session`.
- Interface chỉ tạo khi có ít nhất hai adapter hoặc cần runtime substitution.
- `cmd/*` chỉ load config, wire dependency và quản lý lifecycle.
- Mỗi vertical slice phải xóa production path cũ trong cùng phase cutover; không tạo
  façade hoặc package chuyển tiếp.
