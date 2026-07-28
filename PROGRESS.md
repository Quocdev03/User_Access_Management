# UAM — Implementation Status

> Updated: 2026-07-28

## Release checkpoint

The domain-first modular-monolith restructure is complete.

| Concern | Current state |
| --- | --- |
| Architecture | `httpapi → domain use case → policy/adapter`; manual dependency injection |
| Public API | 41 operations, one semantic owner each, generated OpenAPI and contract tests |
| Database | MySQL migration `000034`, `dirty=false`; canonical schema only |
| Account state | `internal/accountstate` is the single transition-policy owner |
| Sessions | Durable MySQL session/auth-version/reuse history; Redis holds TTL-only state |
| Workflows | Verification, password reset, email change, MFA and mail outbox are durable |
| Runtime | Separate `server`, `worker`, `migrate`, `avatar-migrate`, `bootstrap-admin` binaries |
| Production files | Shared S3-compatible storage; local blob adapter is non-production only |
| Documentation | Concern-based docs plus ADRs; temporary plan and old Markdown retired |

All fourteen implementation phases are complete: security correction, documentation
cutover, schema expansion/backfill, account state, sessions, auth, account,
access/admin, runtime/workers, platform hardening, MFA, HTTP/OpenAPI cutover,
schema contract and release verification.

## Clean-source inventory

```text
cmd/
  server  worker  migrate  avatar-migrate  bootstrap-admin
internal/
  access  account  accountstate  auth  blob  config  contract
  httpapi  jobs  mail  mysqlstore  redisstore  session
pkg/
  apperror  database  hash  jwt  logger  response  validator
docs/
  architecture  data  decisions  domain  openapi  operations  use-cases
migrations/
  000001..000034
```

The removed global layer packages are not runtime compatibility boundaries and must
not be recreated. Redis keys are namespaced under `uam:v1`; MySQL runtime code no
longer reads or writes contracted projections.

## Release verification evidence

- Local `go build ./...`, `go test ./...`, `go vet ./...`, `staticcheck ./...` and
  `go mod verify` pass.
- Migration integration passes for empty-up, historical current-data upgrades,
  duplicate-permission fail-closed behavior and schema `031 → 034` contract.
- Auth, account, access, jobs, MySQL store and Redis integration suites pass on
  isolated disposable databases and Redis.
- Concurrency/failure tests pass for credential changes, verification, email,
  refresh/revoke, last-admin/RBAC, MFA, outbox and worker leases.
- Manual runtime smoke passes liveness/readiness/metrics, bootstrap, register,
  email verification, login/refresh/logout, password reset/change, profile, avatar,
  session/client profile, email change, admin/RBAC, MFA setup and audit export.
- Smoke outbox delivered all six events, produced no dead letters and retained no
  secret payload after delivery.
- The production image builds as non-root and contains all five operational binaries,
  migrations and a health check.
- Local and production runtime env files have the same key inventory as their
  templates; obsolete TLS keys were removed without replacing existing secret values.
- `go test -race -count=1 ./...` passes in a Linux Go 1.26.2 container.
- CI now enforces quality, Linux race, disposable MySQL/Redis integration, image
  build and a SHA-pinned vulnerability scan. It does not auto-deploy production.
- Formatting, whitespace, package/path, Markdown and generated-contract inventory
  gates pass; all disposable databases, processes and temporary artifacts are removed.

## Operational limits

- Production promotion remains platform-specific and requires explicit approval,
  a one-off migration job, readiness and post-deploy smoke checks.
- Redis HA/TLS, provider MySQL TLS and real S3/mail credentials must be verified in
  staging because local Compose cannot prove provider failover or certificate policy.
- Contract migrations are forward-only. After migration 034, rollback is a new
  forward-fix migration rather than an edit or destructive downgrade.
- Exact SLO and alert thresholds require production traffic; observability docs list
  the required signals without inventing thresholds.
