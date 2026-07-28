# MySQL Schema Design

Migration 034 is the current schema head. Account, session and reset columns are
canonical and non-null where required; runtime owners use only the schema below.

## Ownership

| Aggregate | Tables |
| --- | --- |
| Account identity/security | `users` |
| Profile | `user_profiles` |
| Access control | `roles`, `permissions`, `user_roles`, `role_permissions` |
| Session | `sessions`, `refresh_token_history`, client profile table evolved from `devices` |
| Verification workflows | `verification_challenges`, `email_change_requests`, extended `password_reset_tokens` |
| MFA | `user_totp`, `user_totp_recovery_codes` |
| Delivery/audit | `outbox_events`, `audit_logs` |

## Canonical account

`users` keeps login identity, credential and security state:

```text
lifecycle_state ENUM(pending_verification,active,disabled)
email_verified BOOLEAN
administrative_locked_at DATETIME NULL
login_locked_until DATETIME NULL
failed_login_attempts INT
password_change_required BOOLEAN
auth_version BIGINT UNSIGNED
last_login_at and identity/security timestamps
```

`user_profiles` owns `full_name`, `phone`, `date_of_birth`, `avatar_object_key` and `updated_at`, keyed by `user_id`.

## Session

`sessions.access_jti` and `current_refresh_hash` are non-null. `revoked_at`,
`updated_at` and the optional client-profile reference support explicit
rotation/revocation.

`refresh_token_history(token_hash UNIQUE, session_id, user_id, rotated_at, expires_at)` is the durable reuse source. Redis may fast-reject, but a restart must not erase reuse detection.

The table currently named `devices` stores observed client profiles. It may reuse an exact full-user-agent observation, but it has no uniqueness rule that claims OS/browser families identify a physical device.

## Security workflows

`verification_challenges` uses string purpose rather than ENUM and records subject, secret hash, attempts, consumed time and expiry.

`email_change_requests` stores old/new email, account auth-version snapshot, state and expiry. Its challenges reference request ID.

`password_reset_tokens` uses non-null auth version and `consumed_at`; unversioned
tokens were invalidated before contract.

## RBAC and audit

- `roles.is_system` marks protected roles.
- `permissions` gains unique `(resource, action)` only after duplicate check.
- Role/security mutation increments `users.auth_version` transactionally.
- `audit_logs.user_id` changes to nullable `ON DELETE SET NULL`; audit rows are retained.

## MFA, outbox and blob

- `user_totp` stores encrypted secret, key version, last consumed TOTP step and
  confirmed/enabled timestamps.
- Recovery code rows store SHA-256 one-time hashes and `used_at`.
- `outbox_events` stores event type, payload, idempotency key, attempts, availability, claim, delivery and dead-letter metadata.
- Database stores avatar object key, not production filesystem path.
