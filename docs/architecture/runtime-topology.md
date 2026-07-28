# Runtime Topology

```text
Load balancer
  → N × cmd/server
       → MySQL primary
       → Redis HA endpoint
       → S3-compatible object storage

1..N × cmd/worker
  → outbox delivery
  → cleanup guarded by a distributed lease

Deployment job → cmd/migrate
Operator one-off → cmd/bootstrap-admin
```

HTTP, migrations and background work have separate commands. Outbox processing uses
MySQL row claims and bounded concurrency. Cleanup uses a fail-closed Redis lease and
a per-table round-robin budget.

## Runtime invariants

- API replicas do not migrate, run background jobs or retain production files locally.
- Liveness has no backing-service dependency.
- Readiness pings MySQL and Redis directly without rate limiting or IP bans.
- MySQL and Redis pools are budgeted across the total replica count.
- HTTP shutdown waits for inflight requests; workers stop claiming and release work safely.
- Outbox delivery uses idempotency keys, bounded retries/backoff and dead-letter metadata.
- Redis failure closes security paths; provider/cleanup failure after commit never rolls back business data.
