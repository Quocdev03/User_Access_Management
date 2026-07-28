# ADR-004: Atomic TOTP MFA

- Status: Accepted
- Date: 2026-07-28

## Context

The previous TOTP proposal verified a Redis challenge with separate `GET` and `DEL`. Concurrent valid requests could both issue sessions.

## Decision

Use RFC 6238 TOTP, AES-GCM encrypted versioned secret, hashed one-time recovery
codes and an opaque Redis login challenge. Redis Lua atomically creates, claims,
finishes or releases the challenge. Factor validation and the locked
account/auth-version/MFA recheck happen after claim; only the claimant may issue a
session and finish the challenge. TOTP steps and recovery codes are consumed with
conditional MySQL updates.

## Consequences

- MFA login has one winner under concurrency.
- Redis failure is fail-closed; a failure to finish after session commit triggers
  durable auth invalidation as compensation.
- Production needs encryption-key configuration and rotation procedure.
- Recovery codes are displayed once and consumed atomically.
- Disable/regenerate require current password plus MFA and invalidate auth state.
- A maintained RFC 6238 library is preferred over handwritten TOTP.
