# ScanVault

A production-ready Go microservice - and **importable library** - that ingests [Trivy](https://github.com/aquasecurity/trivy) container image scan results and persists them in PostgreSQL for querying and historical analysis.

---

## Features

- `POST /scans` - Ingest raw Trivy JSON; auto-extracts `image_name`, `image_tag`, `image_digest`
- `GET /scans?tag=<tag>` - Query all scans by image tag
- `GET /scans?image=<name>` - Query all scans by image name
- `GET /scans?image=<name>&severity=<level>` - Return only scans that contain at least one matching vulnerability severity
- Optional pagination on list endpoints via `limit` and `offset` query params
- `GET /scans/{id}/vulnerabilities?severity=<level>&pkg=<name>` - Extract filtered vulnerabilities from one stored scan
- `GET /scans/latest?image=<name>` - Fetch the most recent scan for an image
- `GET /health` - Health check
- Query-param fallback (`?image=&tag=`) when Trivy metadata is absent
- Struct-based config via [goconf](https://github.com/tlmanz/goconf) - prints a masked config table on startup
- Structured logging with [zerolog](https://github.com/rs/zerolog)
- Graceful shutdown
- Embedded [goose](https://github.com/pressly/goose) migrations - run automatically at startup, no external tool needed
- PostgreSQL JSONB storage, indexed on `image_tag`, `image_digest`, `image_name`
- Importable as a Go library with a clean `Server` API
- Makefile for every common workflow

---

## Prerequisites

| Tool                                                                                        | Version    |
| ------------------------------------------------------------------------------------------- | ---------- |
| [Go](https://go.dev/dl/)                                                                    | 1.22+      |
| [Docker](https://docs.docker.com/get-docker/) + [Compose](https://docs.docker.com/compose/) | any recent |

---

## Quick Start

### Docker Compose (recommended)

```bash
git clone <repo-url> && cd scanvault
make env-copy        # creates .env from .env.example
make docker-up       # postgres + api (migrations run automatically)
```

API available at `http://localhost:8080`. Tail logs with `make docker-logs`.

### Local (`go run`)

```bash
# 1. Spin up Postgres
docker run -d --name pg \
  -e POSTGRES_DB=scanvault -e POSTGRES_USER=scanvault -e POSTGRES_PASSWORD=scanvault \
  -p 5432:5432 postgres:16-alpine

# 2. Set env vars
make env-copy   # cp .env.example .env

# 3. Run (migrations run automatically on startup)
make run
```

---

## Using as a Library

Yes - this is designed to be embedded in a separate, larger Go codebase as a package. You can run it as a standalone service, or mount its `http.Handler` into your existing server/router.

Add to your project:

```bash
go get github.com/tlmanz/scanvault
```

### Standalone server

```go
import "github.com/tlmanz/scanvault"

srv, err := scanvault.New(ctx, scanvault.Config{
    DatabaseURL: "postgres://user:pass@localhost:5432/db?sslmode=disable",
})
if err != nil {
    log.Fatal(err)
}
defer srv.Close()
srv.Start(ctx) // blocks; handles SIGINT/SIGTERM gracefully
```

Lifecycle notes:
- `Start(ctx)` blocks until shutdown.
- `Close()` is safe to call multiple times.
- When ScanVault creates the pool (from `DatabaseURL`), `Close()` releases it.
- When using `WithDBPool(pool)`, your application owns that pool and must close it.

### Mount on an existing router

```go
// Works with net/http, chi, gorilla/mux, echo, etc.
srv, _ := scanvault.New(ctx, scanvault.Config{DatabaseURL: dsn})
defer srv.Close()
mux.Handle("/trivy/", http.StripPrefix("/trivy", srv.Handler()))
```

Runnable example:
- See [examples/existing-server](examples/existing-server) for a complete app that mounts ScanVault into an existing `net/http` server, adds app-owned routes/middleware, and uses an externally managed pgx pool.

### Functional options

```go
srv, _ := scanvault.New(ctx,
    scanvault.Config{DatabaseURL: dsn},
    scanvault.WithPort(9090),
    scanvault.WithLogLevel("debug"),
    scanvault.WithLogFormat("console"),
    scanvault.WithLogger(myZerologLogger),
)
```

### Use an existing pgx pool

When embedding ScanVault in a larger app, you can pass your existing `*pgxpool.Pool`.
Startup migrations run through that same pool.

```go
pool, _ := pgxpool.New(ctx, dsn)

srv, err := scanvault.New(ctx,
  scanvault.Config{}, // DatabaseURL not required when WithDBPool is provided
  scanvault.WithDBPool(pool),
)
if err != nil {
  log.Fatal(err)
}

// WithDBPool means the pool is externally managed; close it in your app shutdown.
defer pool.Close()
```

### Working with results

```go
import "github.com/tlmanz/scanvault/models"

var scan models.Scan
json.Unmarshal(responseBody, &scan)
fmt.Println(scan.ImageName, scan.ImageTag, scan.CreatedAt)
```

---

## Makefile Targets

```
make help              # List all targets
make run               # go run (loads .env automatically)
make build             # Compile binary → ./bin/scanvault
make run-binary        # Build then run the binary
make clean             # Remove ./bin/
make vet               # go vet ./...
make fmt               # gofmt -w -s .
make lint              # golangci-lint run ./...
make test              # go test -race -coverprofile=coverage.out (test packages)
make migrate           # goose up (requires goose CLI)
make migrate-status    # goose status
make migrate-down      # goose down (roll back last)
make migrate-dry       # goose up --dry-run
make docker-up         # docker compose up --build -d
make docker-down       # Stop containers (keep volumes)
make docker-down-clean # Stop containers + remove volumes
make docker-logs       # Tail api service logs
make docker-restart    # Restart api service only
make env-copy          # cp .env.example .env (safe, no overwrite)
```

---

## Environment Variables

Config is loaded from env vars (or `.env`) via [goconf](https://github.com/tlmanz/goconf). A masked config table is printed to stdout on startup.

### Required

| Variable       | Description    |
| -------------- | -------------- |
| `DATABASE_URL` | PostgreSQL DSN |

### HTTP Server

| Variable             | Default | Description                                       |
| -------------------- | ------- | ------------------------------------------------- |
| `SERVER_PORT`        | `8080`  | Listen port                                       |
| `LOG_LEVEL`          | `info`  | `debug` \| `info` \| `warn` \| `error`            |
| `LOG_FORMAT`         | `json`  | `json` (structured) \| `console` (human-readable) |
| `HTTP_READ_TIMEOUT`  | `15s`   | Request read timeout                              |
| `HTTP_WRITE_TIMEOUT` | `15s`   | Response write timeout                            |
| `HTTP_IDLE_TIMEOUT`  | `60s`   | Keep-alive idle timeout                           |

### pgx Connection Pool

| Variable                 | Default | Description                 |
| ------------------------ | ------- | --------------------------- |
| `DB_MAX_CONNS`           | `25`    | Max open connections        |
| `DB_MIN_CONNS`           | `2`     | Min idle connections        |
| `DB_MAX_CONN_LIFETIME`   | `30m`   | Max connection reuse time   |
| `DB_MAX_CONN_IDLE_TIME`  | `5m`    | Max idle time before close  |
| `DB_HEALTH_CHECK_PERIOD` | `1m`    | Pool liveness ping interval |

### Cleanup Worker

All three default to `0` / `1h`. Setting both `CLEANUP_MAX_AGE` and `CLEANUP_KEEP_PER_IMAGE` to zero disables the worker entirely - no background goroutine is spawned.

| Variable                 | Default   | Description                                 |
| ------------------------ | --------- | ------------------------------------------- |
| `CLEANUP_INTERVAL`       | `1h`      | How often the worker runs                   |
| `CLEANUP_MAX_AGE`        | `0` (off) | Delete scans older than this (e.g. `168h`)  |
| `CLEANUP_KEEP_PER_IMAGE` | `0` (off) | Keep only the N newest scans per image name |

---

## Cleanup Worker

A background goroutine runs on `CLEANUP_INTERVAL` and applies up to two retention policies. The worker only starts if at least one policy is non-zero - if both `CLEANUP_MAX_AGE` and `CLEANUP_KEEP_PER_IMAGE` are `0`, no goroutine is spawned.

### Policy interaction

When **both** policies are set, a scan must fail **both** to be deleted - per-image retention always wins over age:

| `CLEANUP_MAX_AGE` | `CLEANUP_KEEP_PER_IMAGE` | What gets deleted                                                                |
| ----------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `72h`             | off                      | Everything older than 72 h                                                       |
| off               | `10`                     | Every scan past the top 10 per image                                             |
| `72h`             | `10`                     | Only scans that are **both** older than 72 h **AND** ranked #11+ for their image |

**Example:** 15 nginx scans all 5 days old - with `MAX_AGE=72h` + `KEEP_PER_IMAGE=10`, the top 10 are **kept** (protected by count), scans #11–15 are deleted (old + outside the window).

### Library usage

```go
srv, _ := scanvault.New(ctx, scanvault.Config{
    DatabaseURL:         dsn,
    CleanupMaxAge:       7 * 24 * time.Hour, // delete scans older than 1 week
    CleanupKeepPerImage: 10,                 // but always keep the last 10 per image
    CleanupInterval:     30 * time.Minute,   // run every 30 min
})
```

---

## API Reference

### Endpoint Quick Map

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/health` | Service health check |
| `POST` | `/scans` | Ingest one Trivy JSON report |
| `GET` | `/scans?tag=<tag>` | List scans by image tag |
| `GET` | `/scans?image=<name>[&severity=<level>]` | List scans by image name, optionally severity-filtered |
| `GET` | `/scans/{id}/vulnerabilities[?severity=<level>&pkg=<name>]` | Extract vulnerabilities from one stored scan |
| `GET` | `/scans/latest?image=<name>` | Fetch latest scan for an image |

### `POST /scans`

Ingest a raw Trivy JSON scan result. Metadata is auto-extracted from `ArtifactName` and `Metadata`; query params override.

| Query param | Description           |
| ----------- | --------------------- |
| `image`     | Override image name   |
| `tag`       | Override image tag    |
| `digest`    | Override image digest |

**Request body** - raw Trivy JSON:

```json
{
  "ArtifactName": "nginx:1.25",
  "ArtifactType": "container_image",
  "Metadata": {
    "ImageID": "sha256:abc123...",
    "RepoTags": ["nginx:1.25"],
    "RepoDigests": ["nginx@sha256:def456..."]
  },
  "Results": [...]
}
```

**`201 Created`**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "image_name": "nginx",
  "image_tag": "1.25",
  "image_digest": "sha256:abc123...",
  "scan_result": { "...": "..." },
  "created_at": "2026-04-20T14:35:00Z"
}
```

### `GET /scans?tag=<tag>`

Optional pagination query params:
- `limit` (0..500)
- `offset` (>= 0)

**`200 OK`** - `{ "tag": "1.25", "count": 2, "items": [...] }`

When pagination params are provided, response also includes `limit` and `offset`.

Common errors:
- **`400 Bad Request`** for invalid `limit`/`offset`
- **`500 Internal Server Error`** on backend/query failure

### `GET /scans?image=<name>[&severity=<level>]`

Examples:
- `/scans?image=nginx`
- `/scans?image=nginx&severity=CRITICAL`
- `/scans?image=nginx&severity=CRITICAL&limit=50&offset=0`

**`200 OK`** - `{ "image": "nginx", "severity": "CRITICAL", "count": 1, "items": [...] }`

When pagination params are provided, response also includes `limit` and `offset`.

Common errors:
- **`400 Bad Request`** if `limit`/`offset` are invalid
- **`500 Internal Server Error`** on backend/query failure

### `GET /scans/{id}/vulnerabilities?severity=<level>&pkg=<name>`

Both filters are optional. When provided, matching is case-insensitive.

**`200 OK`**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "image_name": "nginx",
  "image_tag": "1.25",
  "severity": "HIGH",
  "pkg": "openssl",
  "count": 1,
  "items": [
    {
      "target": "nginx:1.25 (debian 12.1)",
      "class": "os-pkgs",
      "type": "debian",
      "vulnerability": {
        "VulnerabilityID": "CVE-2026-12345",
        "PkgName": "openssl",
        "Severity": "HIGH"
      }
    }
  ]
}
```

Common errors:
- **`404 Not Found`** if scan ID does not exist
- **`400 Bad Request`** if stored scan payload cannot be interpreted as Trivy vulnerabilities report
- **`500 Internal Server Error`** on backend/query failure

### `GET /scans/latest?image=<name>`

**`200 OK`** - single `Scan` object  
**`404 Not Found`** - `{ "error": "no scans found for image: nginx" }`

### `GET /health`

**`200 OK`** - `{ "status": "ok" }`

---

## Sample `curl` Commands

```bash
# Ingest a scan
curl -s -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "ArtifactName": "nginx:1.25",
    "ArtifactType": "container_image",
    "Metadata": {
      "ImageID": "sha256:a6786163c6f2b5d2813e0c9f3c64e28b23e16a35d76fb9d4caf3fd7e73ef57b1",
      "RepoTags": ["nginx:1.25"],
      "RepoDigests": ["nginx@sha256:6813af4b5b4a5f8c19e3e5f09e77dfa6f27c4e0b9a1e5a75c7b3e2d11c52a49"]
    },
    "Results": [{"Target": "nginx:1.25 (debian 12.1)", "Class": "os-pkgs", "Vulnerabilities": []}]
  }' | jq .

# Fallback: metadata via query params
curl -s -X POST "http://localhost:8080/scans?image=alpine&tag=3.19" \
  -H "Content-Type: application/json" \
  -d '{"ArtifactType":"container_image","Results":[]}' | jq .

# Query by tag
curl -s "http://localhost:8080/scans?tag=1.25" | jq .

# Query by image + severity
curl -s "http://localhost:8080/scans?image=nginx&severity=CRITICAL" | jq .

# List vulnerabilities from a scan (filtered)
curl -s "http://localhost:8080/scans/<scan-id>/vulnerabilities?severity=HIGH&pkg=openssl" | jq .

# Latest scan for an image
curl -s "http://localhost:8080/scans/latest?image=nginx" | jq .
```

---

## Tests

```bash
# Unit tests (no Docker required)
go test -race ./internal/parser/... ./internal/config/... ./internal/handlers/...

# Integration tests (requires Docker - spins up a real Postgres via testcontainers)
go test -race -v ./internal/repository/...

# Everything
make test
```

Test coverage:

- **Parser** - metadata extraction, tag splitting, digest fallback, invalid JSON
- **Config** - defaults, env overrides, validation errors
- **Handlers** - all endpoints via `httptest` + in-memory mock store
- **Repository** - integration tests against a real Postgres container

---

## Project Structure

```
scanvault/
├── config.go                       # Public Config struct + applyDefaults + toInternal
├── server.go                       # Public Server, New(), Handler(), Start()
├── options.go                      # Functional options (WithLogger, WithPort)
├── migrate.go                      # Embedded goose migration runner
├── models/
│   └── scan.go                     # Public Scan type
├── cmd/server/main.go              # Thin CLI entrypoint
├── internal/
│   ├── config/config.go            # goconf env-based config
│   ├── db/db.go                    # pgx/v5 connection pool
│   ├── handlers/scan_handler.go    # HTTP handlers (uses Store interface)
│   ├── parser/trivy.go             # Trivy JSON metadata extractor
│   ├── repository/scan_repo.go     # PostgreSQL queries + cleanup methods
│   └── worker/cleanup.go           # Background cleanup worker
├── migrations/
│   ├── 001_create_scans.sql        # Goose SQL migration (Up + Down)
│   └── embed.go                    # //go:embed *.sql
├── Dockerfile                      # Multi-stage: golang builder + distroless
├── docker-compose.yml              # postgres + api (no separate migrate service)
├── Makefile
└── .env.example
```

---

## Database Schema

```sql
CREATE TABLE scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name    TEXT        NOT NULL,
    image_tag     TEXT        NOT NULL DEFAULT '',
    image_digest  TEXT        NOT NULL DEFAULT '',
    scan_result   JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_image_tag    ON scans(image_tag);
CREATE INDEX idx_scans_image_digest ON scans(image_digest);
CREATE INDEX idx_scans_image_name   ON scans(image_name);
CREATE INDEX idx_scans_created_at   ON scans(created_at DESC);
```

---

## Tech Stack

| Layer      | Library                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------- |
| HTTP       | [Gin](https://github.com/gin-gonic/gin)                                                      |
| Database   | [pgx/v5](https://github.com/jackc/pgx)                                                       |
| Migrations | [goose/v3](https://github.com/pressly/goose) (embedded)                                      |
| Config     | [goconf](https://github.com/tlmanz/goconf) + [caarlos0/env](https://github.com/caarlos0/env) |
| Logging    | [zerolog](https://github.com/rs/zerolog)                                                     |
| Tests      | [testcontainers-go](https://github.com/testcontainers/testcontainers-go)                     |
| Runtime    | [distroless/static](https://github.com/GoogleContainerTools/distroless)                      |
