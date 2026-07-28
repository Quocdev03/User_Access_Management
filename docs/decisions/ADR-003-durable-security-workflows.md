# ADR-003: Durable Security Workflows

- Status: Accepted
- Date: 2026-07-28

## Context

Session revocation, refresh reuse and email change currently split durable MySQL data and Redis keys. Redis restart or cross-store partial failure can lose business/security state.

## Decision

MySQL owns account, session, refresh history, verification request, email change, reset, audit and outbox state. Redis owns only namespaced TTL state: rate/ban, JTI, refresh fast marker, MFA challenge and worker lease.

## Consequences

- Refresh reuse survives Redis restart.
- Email-change request and challenges commit atomically.
- Redis remains fail-closed for immediate security checks without becoming business source of truth.
- Mail becomes an outbox side effect with bounded worker.
- Additional tables and worker lifecycle are accepted for consistency and scale.
