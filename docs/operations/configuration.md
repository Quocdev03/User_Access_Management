# Configuration

Runtime loads `.env` through Viper and allows environment variables to override it. Duration values require units such as `15m` or `900s`.

## Current variables

| Group | Variables | Notes |
| --- | --- | --- |
| App | `APP_ENV`, `APP_PORT`, `APP_FRONTEND_URL`, `TRUSTED_PROXIES` | Empty trusted proxies means forwarded IP headers are not trusted |
| MySQL | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_TLS_MODE`, `DB_TLS_CA_FILE`, `DB_TLS_ALLOW_INSECURE`, `DB_MAX_OPEN_CONNS`, `DB_MAX_IDLE_CONNS`, `DB_CONN_MAX_LIFETIME`, `DB_CONN_MAX_IDLE_TIME` | TLS mode is `disable`, `verify` or `skip-verify`; pool values are per replica |
| Redis | `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_POOL_SIZE`, `REDIS_MIN_IDLE_CONNS` | Host may be `redis://` or `rediss://` URL; pool values are per process |
| JWT | `JWT_SECRET`, `JWT_ACCESS_EXPIRY`, `JWT_REFRESH_EXPIRY` | Secret validation currently requires at least 16 characters |
| Mail | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | `smtp.resend.com` selects current HTTPS Resend adapter |
| Blob | `BLOB_PROVIDER`, `BLOB_LOCAL_ROOT`, `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_PUBLIC_BASE_URL`, `S3_FORCE_PATH_STYLE` | Production requires `s3`; local is non-production only; static credentials must be supplied as a pair |
| Security | `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`, `RATE_LIMIT_BAN_DURATION`, `MAX_FAILED_ATTEMPTS`, `LOCK_DURATION`, `JSON_MAX_BYTES`, `MULTIPART_MAX_BYTES` | Global token bucket is a coarse DoS boundary; valid sensitive requests have a second bucket |
| Workflow expiry | `OTP_EXPIRY`, `OTP_MAX_ATTEMPTS`, `OTP_PEPPER`, `PASSWORD_RESET_EXPIRY`, `EMAIL_CHANGE_EXPIRY` | Mail text and durable expiry use the same configuration |
| MFA | `MFA_ISSUER`, `MFA_ACTIVE_KEY_VERSION`, `MFA_ENCRYPTION_KEYS`, `MFA_CHALLENGE_TTL`, `MFA_MAX_ATTEMPTS`, `MFA_RECOVERY_CODE_COUNT` | Key ring entries are `version:base64-encoded-32-byte-key`, separated by commas |
| Session | `MAX_SESSIONS_PER_USER` | Default 10; `0` means unlimited |
| Cleanup | `CLEANUP_INTERVAL`, `CLEANUP_BATCH_SIZE`, `CLEANUP_TABLE_BUDGET`, `CLEANUP_TIMEOUT`, `CLEANUP_LEASE_TTL`, `OUTBOX_RETENTION`, `AUDIT_RETENTION` | Separate worker; Redis lease fail-closed, fair per-table budget; audit retention `0` disables audit deletion |
| Outbox | `OUTBOX_POLL_INTERVAL`, `OUTBOX_BATCH_SIZE`, `OUTBOX_CLAIM_TTL`, `OUTBOX_TIMEOUT`, `OUTBOX_MAX_CONCURRENT` | Bounded claim/delivery, stale-claim recovery and retry |
| Observability | `READINESS_TIMEOUT`, `METRICS_TOKEN` | Production registers `/metrics` only when a token is configured |
| Compose only | `DB_ROOT_PASSWORD` | Used by MySQL container, not application config |
| Bootstrap CLI only | `UAM_BOOTSTRAP_ADMIN_PASSWORD` | Required only while running `cmd/bootstrap-admin`; inject from secret store and remove immediately |

## Validation

- Environment name, application/database/Redis/SMTP ports, required MySQL fields,
  frontend URL and JWT secret are checked at startup.
- Production requires `DB_TLS_MODE=verify`. `disable` or `skip-verify` requires the
  explicit emergency flag `DB_TLS_ALLOW_INSECURE=true`; this flag is not normal
  deployment configuration.
- MySQL defaults per process: 25 open, 10 idle, 5 minute lifetime and 1 minute
  idle time. Redis defaults to pool size 20. Operators must keep
  `replicas × per-process budget` within each provider limit.
- JWT/rate/lock/OTP durations below one second are rejected.
- Cleanup defaults: 1 hour interval, batch 1000, per-table budget 5000, 2 minute
  timeout, lease TTL 3 minutes and delivered/dead outbox retention 7 days.
- Outbox defaults: 1 second poll, batch 20, claim TTL 2 minutes, timeout 30 seconds and concurrency 4.
- Production without `OTP_PEPPER` fails startup.
- Production without a valid MFA key ring, or with an active version absent from
  the ring, fails startup. Development/test may derive a deterministic
  development-only key from `JWT_SECRET`; it must never be reused in production.
- MFA defaults are a 5 minute challenge, 5 attempts and 10 recovery codes. Key
  rotation adds a new version, deploys readers with both keys, switches the active
  version, then removes the old key only after every stored secret is re-encrypted
  or MFA is re-enrolled.
- Production with local blob storage fails startup. S3 requires region, bucket and
  an HTTPS public base URL; credentials may come from workload identity.
- JSON bodies default to 64 KiB; multipart bodies default to 3 MiB. DTO byte
  limits are enforced before password hashing or database work.
- Readiness defaults to a 2 second dependency deadline. Metrics are open only in
  non-production without a token; production omits the route when the token is empty.

## Secret policy

- Never commit actual JWT, DB, Redis, mail, MFA or bootstrap secrets.
- Templates contain placeholders only.
- Do not log tokens, OTP, reset links, passwords or encryption keys.
- Rotation of credential/auth/MFA keys requires a documented data and session invalidation procedure.
