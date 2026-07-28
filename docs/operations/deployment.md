# Deployment

## Release order

1. Build one immutable image and run CI quality, race, integration and image-scan gates.
2. Apply immutable migrations once with the image's `migrate` binary.
3. Deploy stateless `server` replicas and wait for readiness.
4. Deploy one or more `worker` processes; outbox claims are concurrent-safe and cleanup is lease-protected.
5. Run public-contract and smoke checks before routing full traffic.

The repository CI validates release artifacts but does not deploy production.
Production promotion requires an explicit operator approval and a platform-specific
migration job. A webhook response alone is not deployment success.

Before the one-off avatar cutover, run `avatar-migrate` with the previous upload
volume mounted read-only. It changes the database only after upload and SHA-256
download verification.

See [runtime topology](../architecture/runtime-topology.md) and
[migration strategy](../data/migration-strategy.md).

## Backing services and configuration

- MySQL 8/InnoDB with verified TLS and a least-privilege application user.
- Redis HA endpoint with authentication and TLS where available.
- Durable S3-compatible avatar storage.
- Mail provider reached only by the outbox worker.

Production requires `DB_TLS_MODE=verify`. Configure `DB_TLS_CA_FILE` when the
provider CA is absent from system trust. `DB_TLS_ALLOW_INSECURE=true` is an
emergency-only override with an explicit expiry and rollback owner.

Inject S3 credentials from a secret manager, or leave both static credential
variables empty when workload identity is available. Pool sizes are per process;
their sum must fit the provider-wide connection budget.

## Rollback

- Keep mixed application versions only during an explicitly supported expand window.
- Drain old API and worker replicas before a contract migration.
- Before contract, roll back the application while the expanded schema is compatible.
- After contract, recover through a new forward-fix migration; never edit an applied migration.
- Verify readiness, public contract, outbox lag/dead-letter count and error rate after rollback.

## Bootstrap

Run `bootstrap-admin` as an audited one-off with
`UAM_BOOTSTRAP_ADMIN_PASSWORD` supplied by a short-lived secret. The production
image contains this binary; no administrator credential is seeded or stored in env files.
