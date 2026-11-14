# Redis Contract

Redis is fail-closed for security decisions, but never owns durable account,
session-revocation or workflow state.

> [!IMPORTANT]
> **Quy chuẩn ký hiệu Hash Tag và Tham số (Redis Cluster Hash Tag Convention)**:
> - Ký hiệu `{...}` (dấu ngoặc nhọn) trong tài liệu này **chỉ được sử dụng duy nhất** ở những vị trí thực sự là **Redis Cluster Hash Tag** (nhằm đảm bảo các key liên quan cùng được băm vào một cluster shard khi chạy multi-key Lua scripts, ví dụ `{identity}` và `{challenge}`).
> - Toàn bộ các biến tham số thông thường khác bắt buộc dùng ký hiệu `<param>` (ví dụ `<scope>`, `<jti>`, `<hash>`, `<job>`) để tránh gây nhầm lẫn với cơ chế Cluster Hash Tag của Redis.

## Supported keys

| Pattern | Purpose | TTL |
| --- | --- | --- |
| `uam:v1:security:{identity}:bucket:<scope>` | Atomic token bucket; `{identity}` là Redis Cluster Hash Tag | Twice the refill window |
| `uam:v1:security:{identity}:violations:<scope>` | Rejected valid-request count updated by limiter Lua script; `{identity}` là Redis Cluster Hash Tag | Rate window |
| `uam:v1:security:{identity}:ban` | Temporary identity/IP ban; `{identity}` là Redis Cluster Hash Tag | Ban duration |
| `uam:v1:jti:<jti>` | Revoked access-token JTI | Remaining access-token TTL |
| `uam:v1:refresh-reuse:<hash>` | Fast reuse marker; MySQL history is authoritative | Remaining refresh-token TTL |
| `uam:v1:mfa:{challenge}` | Opaque MFA login challenge and claim state; `{challenge}` là Redis Cluster Hash Tag | MFA challenge TTL |
| `uam:v1:worker-lease:<job>` | Cleanup worker lease | Configured lease TTL |

Every key is namespaced, versioned and has an explicit TTL. The runtime does not
read unnamespaced token or lease keys.

The MFA challenge store uses Lua for create, claim, finish and release. Invalid
completion increments attempts and releases or deletes at the limit; successful
completion deletes the key; a system failure releases the claim without spending
an attempt.

## Failure behavior

- Rate, ban, JTI and MFA errors return service unavailable or the owning use-case error.
- Redis refresh markers are optimizations; durable reuse history remains in MySQL.
- Lease failure stops new cleanup claims but does not undo committed business data.
