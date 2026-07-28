# UAM Documentation

Tài liệu mô tả hệ thống domain-first đang chạy ở migration `000034`. Khi code và
docs lệch nhau, executable source trong bảng dưới là nguồn kiểm chứng và tài liệu
phải được sửa trong cùng thay đổi.

## Source of truth

| Concern | Owner |
| --- | --- |
| Public HTTP contract | `internal/httpapi` + generated OpenAPI; 41 operations hiện có là compatibility baseline |
| Current package/runtime behavior | Go source + tests |
| Current MySQL schema | `migrations/*.sql` đã áp dụng |
| Architecture and data design | `docs/architecture/`, `docs/data/schema-design.md`, ADR |
| Domain invariant | `docs/domain/` + invariant tests khi được triển khai |
| Business use case | `docs/use-cases/` + contract tests |
| Runtime configuration | `internal/config/config.go` + `.env*.example` |
| Implementation and release status | `PROGRESS.md` |

## Navigation

| Area | Documents |
| --- | --- |
| Architecture | [System context](architecture/system-context.md), [modules](architecture/modules.md), [runtime topology](architecture/runtime-topology.md), [security boundaries](architecture/security-boundaries.md) |
| Domain | [Account state](domain/account-state.md), [authentication](domain/authentication.md), [session](domain/session.md), [access control](domain/access-control.md) |
| Data | [Current schema](data/current-schema.md), [schema design](data/schema-design.md), [Redis keys](data/redis-keys.md), [migration strategy](data/migration-strategy.md) |
| Use cases | [Route matrix](use-cases/README.md), [authentication](use-cases/authentication.md), [account](use-cases/account.md), [session](use-cases/session.md), [access/admin](use-cases/access-admin.md), [MFA](use-cases/mfa.md) |
| Operations | [Local development](operations/local-development.md), [configuration](operations/configuration.md), [deployment](operations/deployment.md), [observability](operations/observability.md) |
| Decisions | [ADR index](decisions/README.md) |
| HTTP reference | `openapi/` — generated, không sửa tay |

## Documentation rules

- Mỗi invariant chỉ có một owner theo concern; tài liệu khác liên kết tới owner.
- OpenAPI trong `docs/openapi/` được generate bằng `swag`, không sửa tay.
- Git history lưu lịch sử; không tạo archive, redirect stub hoặc bản sao Markdown.
