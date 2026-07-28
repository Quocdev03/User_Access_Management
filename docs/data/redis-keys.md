# Redis Contract

Redis is fail-closed for security decisions, but never owns durable account,
session-revocation or workflow state.

## Supported keys

| Pattern | Purpose | TTL |
| --- | --- | --- |
| `uam:v1:security:{identity}:bucket:{scope}` | Atomic token bucket; braces form the Redis Cluster hash tag | Twice the refill window |
| `uam:v1:security:{identity}:violations:{scope}` | Rejected valid-request count updated by the limiter Lua script | Rate window |
| `uam:v1:security:{identity}:ban` | Temporary identity/IP ban | Ban duration |
| `uam:v1:jti:{jti}` | Revoked access-token JTI | Remaining access-token TTL |
| `uam:v1:refresh-reuse:{hash}` | Fast reuse marker; MySQL history is authoritative | Remaining refresh-token TTL |
| `uam:v1:mfa:{challenge}` | Opaque MFA login challenge and claim state | MFA challenge TTL |
| `uam:v1:worker-lease:{job}` | Cleanup worker lease | Configured lease TTL |

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
