# ADR-001: Domain-First Modular Monolith

- Status: Accepted
- Date: 2026-07-28

## Context

Global `handler/service/repository` folders have produced large services, cross-folder changes and duplicated state rules. The system remains one cohesive account/auth/access domain; microservices would add distributed transaction and operational cost.

## Decision

Organize internal code by domain (`auth`, `account`, `session`, `access`) with lightweight layers at boundaries (`httpapi`, stores, mail, blob, jobs). Use manual dependency injection. Replace one vertical slice at a time and delete its legacy path before phase completion.

## Consequences

- Related use-case logic and tests become colocated.
- Package dependency rules replace global layer naming.
- Internal APIs may break during safe cutover; public HTTP remains compatible.
- No generic base repository/service, broad event bus or interface-per-use-case.
- A temporary shim requires owner, expiry and explicit deletion task.
