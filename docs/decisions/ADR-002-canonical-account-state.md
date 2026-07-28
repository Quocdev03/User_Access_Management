# ADR-002: Canonical Account State

- Status: Accepted
- Date: 2026-07-28

## Context

Before cutover, one `status` field represented email lifecycle, administrative lock
and brute-force lock. Mutation paths could overwrite each other and session
invalidation was split between MySQL and Redis.

## Decision

Split lifecycle, administrative lock and login lock into orthogonal fields. Introduce durable `auth_version`. `accountstate` exclusively owns transition and effective public status calculation. Preserve public `active|inactive|locked` through projection.

## Consequences

- State collisions become explicit and testable.
- Password or brute-force recovery cannot clear admin lock.
- Security mutation increments auth version in its transaction.
- Middleware initially reads version from MySQL for correctness; caching requires benchmark and stale-window contract.
- Rollout requires dual-write, backfill and mismatch gate before old columns are dropped.

Implementation completed in migrations 020–034; the old account-state columns were
dropped only after the migration-032 mismatch gate passed.
