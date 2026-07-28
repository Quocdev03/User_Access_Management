# Observability

## Current

Every HTTP response carries `X-Request-ID`. A valid caller-supplied ID is preserved;
otherwise the server generates one. Zap request logs contain request ID, method,
normalized route, status, latency and anonymous/authenticated client class without
tokens or request bodies.

`GET /health` is dependency-free liveness. `GET /health/ready` checks MySQL and
Redis under `READINESS_TIMEOUT`; neither endpoint passes through the API limiter or
IP ban. Dependency errors return only `DOWN`, while wrapped causes stay in server
logs.

`GET /metrics` returns bounded JSON counters for HTTP status/latency/inflight/rate
rejects, MySQL/Redis pools and Go runtime memory/goroutines/GC. In production the
route exists only when `METRICS_TOKEN` is configured and requires
`Authorization: Bearer <token>`; an invalid token returns 404.

## Operational signals

| Signal | Minimum fields/measurements |
| --- | --- |
| Request log | request ID, method, normalized route, status, latency, client identity classification |
| Security audit | actor, action, resource, result, request metadata; no secret payload |
| Metrics | request rate/error/latency, DB/Redis pool, rate-limit rejects, auth failures, outbox lag/retry/dead-letter, worker lease |
| Trace | Not implemented yet; future HTTP → use case → MySQL/Redis/provider boundaries must use secret-safe attributes |
| Health | dependency-free liveness; bounded MySQL/Redis readiness |

## SLO starting points

Define measurable targets before alert thresholds. At minimum track API availability, p95/p99 latency, readiness failures, outbox oldest-event age and dead-letter count. Exact targets require production traffic and are intentionally not invented here.

## Logging safety

- Never log passwords, raw JWT/refresh token, OTP, reset token, TOTP secret/recovery code, provider API key or full authorization header.
- Hash or redact identity where logs leave the security boundary.
- Expected business failures are structured at appropriate level; provider/database failures include wrapped cause and request ID.
- Best-effort cleanup failure logs warning/error with object/event ID and remains retryable.
