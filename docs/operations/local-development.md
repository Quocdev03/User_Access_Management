# Local Development

The current Compose file starts infrastructure only: MySQL, Redis and Mailpit. It does not define an `app` service.

## Prerequisites

- Go version declared in `go.mod`
- Docker + Docker Compose
- Optional: `air`, `swag`, `golang-migrate`, Make

## Start

```bash
docker compose up -d
cp .env.example .env
go run ./cmd/migrate
go run ./cmd/worker
go run ./cmd/server
```

`cmd/server` never applies migrations or starts background jobs. Run migration once,
then keep `cmd/worker` and `cmd/server` in separate terminals.

Mailpit:

- SMTP from host: `127.0.0.1:1026`
- Inbox: `http://localhost:8025`

Docker maps host `1026` to container `1025`.

If host port `6379` is reserved, set both `REDIS_PORT` and
`REDIS_PUBLISHED_PORT` to the same available host port; the container still
listens on `6379`.

## Verify

```bash
curl http://localhost:8080/health
curl http://localhost:8080/health/ready
go test ./...
```

Development-only UI:

- API tester: `http://localhost:8080/`
- Swagger: `http://localhost:8080/swagger/index.html`

## Available automation

Current Make targets include `run`, `worker`, `build`, `migrate`, migration
maintenance, `avatar-migrate`, Swagger, test and Compose helpers. There is no
`make seed` target.

On Windows use `make.cmd` where the repository provides an equivalent command.

## Data reset

`docker compose down -v` removes local MySQL/Redis volumes and is destructive. Use it only for disposable development data. Production uses forward migrations and never recreates the database to resolve drift.

No shared administrator is seeded. After migrations, run the audited one-off command:

```powershell
$env:UAM_BOOTSTRAP_ADMIN_PASSWORD = '<secret-from-password-manager>'
go run ./cmd/bootstrap-admin `
  --username first_admin `
  --email admin@example.com `
  --full-name 'First Administrator' `
  --phone 0900000000 `
  --date-of-birth 1990-01-01
Remove-Item Env:UAM_BOOTSTRAP_ADMIN_PASSWORD
```

The command accepts the password only from the process environment, validates the existing password policy and rejects the retired bootstrap credential.
