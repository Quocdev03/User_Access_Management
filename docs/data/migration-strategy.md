# Migration Strategy

Production changes use forward-only expand/migrate/contract. Applied migrations are immutable.

## Sequence

```text
security correction
→ expand nullable/defaulted schema
→ separate batched backfill
→ deploy dual-write/read-new
→ cut over one vertical slice
→ consistency verification
→ contract migration
```

## Required gates

- DDL and data backfill use separate migrations/jobs.
- Do not add `NOT NULL` to populated tables before backfill.
- Do not drop old schema until old application replicas have drained.
- Large backfill is batched, resumable and tested on production-sized copy.
- Record lock duration, query plan and rollback/irreversibility note.
- Production rollback is a forward-fix migration.
- A phase cannot finish while both old and new production paths own the same behavior.

## State backfill

| Previous projection | Canonical value |
| --- | --- |
| `status=active` | `lifecycle_state=active` |
| `inactive && !email_verified` | `pending_verification` |
| `inactive && email_verified` | `disabled` |
| `locked && locked_until IS NULL` | `administrative_locked_at=updated_at` |
| `locked && locked_until IS NOT NULL` | `login_locked_until=locked_until` |
| `must_change_password` | `password_change_required` |

Dual-write is temporary and has a consistency query. Contract requires mismatch count zero.

## Other transitions

- Revoke/delete sessions with empty JTI before adding `NOT NULL`.
- Refresh history starts at cutover; historical rotations cannot be reconstructed.
- Drain or invalidate live OTP/email-change flows rather than fabricate missing aggregate state.
- Invalidate legacy password-reset tokens when auth version is introduced.
- Keep existing device rows. Migration 029 removes the false OS/browser physical-identity unique key; its down migration is intentionally non-destructive because later observations cannot be merged safely.
- `cmd/avatar-migrate` copies local avatars to object storage, downloads and verifies
  SHA-256, then conditionally changes the canonical key/public URL in one transaction.
- Add `roles.is_system`; check permission duplicates before unique constraint.
- Change audit FK without deleting audit data.
- Migration 019 removes the historical bootstrap record only when username, email and known password hash all still match; modified records remain for operator audit.

## Canonical schema expand/backfill inventory

| Migration | Type | Result |
| --- | --- | --- |
| `000020` | DDL expand | Canonical account columns and `user_profiles` |
| `000021` | data backfill | Account-state mapping and profile copy |
| `000022` | DDL expand | Session target columns and durable refresh history |
| `000023` | data backfill | Delete sessions without JTI; copy valid session fields |
| `000024` | DDL expand | Verification/email-change workflows and reset metadata |
| `000025` | DDL expand | System-role marker, permission pre-index and audit FK |
| `000026` | data validation | Backfill system roles; fail without deleting duplicate permission semantics |
| `000027` | DDL expand | Durable outbox |
| `000028` | DDL constraint | Unique permission `(resource, action)` after validation |
| `000029` | DDL constraint removal | Preserve client profiles and remove false physical-device uniqueness |
| `000030` | data migration | Preserve live legacy email-verification challenge hashes and attempts |
| `000031` | DDL expand | Encrypted TOTP enrollment and one-time recovery-code tables; no existing-row rewrite |
| `000032` | data finalization | Final catch-up, invalidate unversioned reset tokens and abort on any projection/workflow mismatch |
| `000033` | DDL contract | Drop account/profile mirrors; enforce canonical `NOT NULL` and lifecycle indexes |
| `000034` | DDL contract | Drop old session projections, reset flag and drained OTP table |

## Completed contract gate

The canonical cutover used bounded dual-write and catch-up for replicas on the expand schema.
All application owners later moved to canonical reads. Before contract, the following
historical queries returned zero on current data; migration 032 repeated the catch-up
and encoded equivalent fail-closed checks. These queries reference columns removed by
033/034 and therefore apply only to a schema-031 preflight copy:

```sql
SELECT COUNT(*) AS missing_account_state
FROM users
WHERE lifecycle_state IS NULL
   OR password_change_required IS NULL
   OR auth_version IS NULL;

SELECT COUNT(*) AS missing_profile
FROM users u
LEFT JOIN user_profiles p ON p.user_id = u.id
WHERE p.user_id IS NULL;

SELECT COUNT(*) AS session_projection_mismatch
FROM sessions
WHERE jti IS NULL
   OR jti = ''
   OR access_jti IS NULL
   OR current_refresh_hash IS NULL;

SELECT COUNT(*) AS duplicate_permission_semantics
FROM (
    SELECT resource, action
    FROM permissions
    GROUP BY resource, action
    HAVING COUNT(*) > 1
) duplicates;
```

Migration 021/023 rollback is intentionally a no-op because copied values cannot be distinguished from later canonical writes and deleted unusable sessions cannot be reconstructed. Migration 026 aborts on duplicate permission semantics instead of choosing or deleting production records.

Migrations 032–034 are forward-only. The data finalization cannot reactivate
unversioned reset tokens, and the contract migrations cannot reconstruct authoritative
values for deleted mirrors. Rollback requires a new forward-fix migration. Operators
must drain old replicas and run the schema-031 preflight before applying 033/034.

## Vertical replacement checklist

Inventory route, handler, service, repository, model, schema, Redis key, config, test, docs, comment and DI wiring; lock public contract; expand; replace; delete old path; run reference sweep and verification.
