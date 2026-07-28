# Current MySQL Schema

**Verified against:** migrations `000001`–`000034`. Migration files are immutable source of truth.

Schema canonical đã contract sau consistency gate. State/profile/session projection cũ
và `otp_codes` không còn tồn tại; các canonical security columns bắt buộc `NOT NULL`.

All business tables use InnoDB and `utf8mb4_unicode_ci`.

## Tables

| Table | Durable responsibility | Important constraints |
| --- | --- | --- |
| `users` | Canonical identity, credential và account security state | unique username/email; lifecycle/verification indexes |
| `user_profiles` | Canonical profile and avatar object key | one row per user; user FK cascade |
| `roles` | RBAC roles | unique name |
| `permissions` | Named resource/action permissions | unique name and `(resource, action)` |
| `user_roles` | User-role assignments | unique `(user_id, role_id)` |
| `role_permissions` | Role-permission assignments | unique `(role_id, permission_id)` |
| `sessions` | Current refresh hash, access JTI, client profile và revocation state | unique current refresh hash; non-null access JTI |
| `refresh_token_history` | Durable refresh reuse history | unique token hash; session FK set null |
| `devices` | Observed client profiles | indexed by user; no physical-device uniqueness claim |
| `password_reset_tokens` | Versioned hashed reset token | unique token hash; non-null auth version; nullable consumed time |
| `email_change_requests` | Durable email-change aggregate | UUID request ID; user/state/expiry indexes |
| `verification_challenges` | Request-scoped verification | unique request/purpose/subject |
| `outbox_events` | Durable delivery queue | unique idempotency key; claim/delivery indexes |
| `audit_logs` | Append-oriented audit record | nullable user FK with `ON DELETE SET NULL` |
| `user_totp` | Encrypted TOTP enrollment and replay state | one row per user; user FK cascade |
| `user_totp_recovery_codes` | One-time recovery-code hashes | unique hash per user; unused index |

## `users`

```text
id BIGINT UNSIGNED PK
username VARCHAR(50) UNIQUE
email VARCHAR(255) UNIQUE
password_hash VARCHAR(255)
lifecycle_state ENUM(pending_verification,active,disabled) NOT NULL
email_verified BOOLEAN
administrative_locked_at DATETIME NULL
login_locked_until DATETIME NULL
failed_login_attempts INT
password_change_required BOOLEAN NOT NULL
auth_version BIGINT UNSIGNED NOT NULL
last_login_at DATETIME NULL
created_at, updated_at DATETIME
```

Profile fields and avatar object key belong only to `user_profiles`. Production resolves
`avatar_object_key` through the configured blob adapter.

## Sessions and clients

`sessions` uses non-null `access_jti` and `current_refresh_hash`, optional
`client_profile_id`, `revoked_at` and `updated_at`. Migration 034 removed the four
old projections after mismatch count reached zero. Migration 029 removed the false
`(user_id, os, browser)` physical-identity constraint without deleting observations.
The public `/devices` name remains backward-compatible but does not claim physical identity.

## Verification and reset

- Email verification uses only request-scoped `verification_challenges`; `otp_codes`
  was removed after live email challenges were preserved and other active OTP types drained.
- Reset token is hashed and has non-null `auth_version`, expiry and `consumed_at`.
- Registration and email change use request-scoped `verification_challenges`; email change state is durable in `email_change_requests`.

## RBAC and audit

Seeded roles `admin`, `moderator`, `user` have `is_system=1`. Permissions are unique by `(resource, action)` after duplicate validation. `audit_logs` keeps JSON old/new values and actor/request metadata; deleting an actor now sets `user_id=NULL`.

## MFA

`user_totp` stores AES-GCM ciphertext, encryption-key version, the last consumed
TOTP step and pending/confirmed/enabled timestamps. `user_totp_recovery_codes`
stores SHA-256 hashes and `used_at`; plaintext recovery codes are returned only at
confirmation or regeneration. Migration 031 is DDL-only and preserves all existing
accounts and sessions.

## Migration inventory

| Range | Meaning |
| --- | --- |
| `000001`–`000010` | Base user, RBAC, session/device, OTP/reset and audit tables |
| `000011` | Seed roles and permissions |
| `000012` | Historical bootstrap admin seed; retained as immutable migration history |
| `000013`–`000017` | Password-change flag, notify permission and bootstrap flag corrections |
| `000018` | Normalize/dedupe devices and add `(user_id, os, browser)` unique key |
| `000019` | Delete the untouched known bootstrap account; preserve/anonymize its audit rows |
| `000020`–`000021` | Expand and backfill canonical account state plus `user_profiles` |
| `000022`–`000023` | Expand session rotation fields, create refresh history and remove sessions without JTI |
| `000024` | Create durable verification/email-change workflow schema and expand reset tokens |
| `000025`–`000026` | Expand/backfill system-role and audit ownership; reject duplicate permission semantics |
| `000027` | Create durable outbox |
| `000028` | Enforce unique permission `(resource, action)` after validation |
| `000029` | Drop false physical-device uniqueness on `(user_id, os, browser)` without deleting observations |
| `000030` | Copy live legacy email-verification hashes/attempts/expiry into durable challenges |
| `000031` | Create encrypted TOTP enrollment and one-time recovery-code tables |
| `000032` | Final canonical catch-up, invalidate unversioned reset tokens and fail-closed consistency validation |
| `000033` | Contract account/profile mirrors; enforce canonical account `NOT NULL` and indexes |
| `000034` | Contract session projections, reset `is_used` and drained `otp_codes` |

Do not edit these files after deployment. Correct them with new forward migrations.
