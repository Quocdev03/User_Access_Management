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
| `httpapi` | Router, middleware composition, bind/validate, HTTP endpoint, response mapping, Swagger annotations |
| `auth` | Register, email verification, login, refresh, password và MFA |
| `account` | Profile, email change, avatar |
| `session` | Issue, rotate, revoke, list session và observed client profile |
| `access` | RBAC, admin user/role mutation, last-admin guard |
| `accountstate` | Pure transition policy và effective public status |
| `mysqlstore` | MySQL query/command; không gọi Redis/mail/blob |
| `redisstore` | TTL state và atomic Redis operation |
| `mail`, `blob` | Runtime adapters; interface chỉ tại boundary có nhiều implementation |
| `jobs` | Outbox delivery, cleanup, scheduled maintenance |

## HTTP adapter file naming

`internal/httpapi` gom toàn bộ transport concern trong một package owner duy nhất.
Tên file phản ánh trách nhiệm HTTP cụ thể, không tạo lại các global layer package đã
bị loại bỏ:

| File pattern | Trách nhiệm |
| --- | --- |
| `*_endpoint.go` | Bind request, gọi domain use case và map response/error cho endpoint HTTP |
| `*_contract.go` | Request/response contract và metadata dùng ở HTTP boundary |
| `*_routes.go` | Đăng ký route và gắn middleware cho từng nhóm endpoint |
| `*_middleware.go` | Authentication, authorization, rate limit, CORS và HTTP hardening |
| `http.go` | Composition root của HTTP router và middleware |

Domain không import các file hoặc package HTTP này; việc đổi tên chỉ làm rõ ownership
và không thay đổi public route, request/response contract hay semantic use case.

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
