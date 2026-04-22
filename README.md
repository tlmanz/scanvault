[![CI](https://github.com/tlmanz/scanvault/actions/workflows/ci.yml/badge.svg)](https://github.com/tlmanz/scanvault/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tlmanz/scanvault/actions/workflows/codequality.yml/badge.svg)](https://github.com/tlmanz/scanvault/actions/workflows/codequality.yml)
[![Coverage Status](https://coveralls.io/repos/github/tlmanz/scanvault/badge.svg)](https://coveralls.io/github/tlmanz/scanvault)
![Open Issues](https://img.shields.io/github/issues/tlmanz/scanvault)
[![Go Report Card](https://goreportcard.com/badge/github.com/tlmanz/scanvault)](https://goreportcard.com/report/github.com/tlmanz/scanvault)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/tlmanz/scanvault)

# ScanVault

A production-ready Go microservice that ingests [Trivy](https://github.com/aquasecurity/trivy) container image scan results and persists them in PostgreSQL for querying, deduplication, and historical analysis.

---

## Features

### Scan Ingestion
- `POST /scans` — Ingest raw Trivy JSON; auto-extracts `image_name`, `image_tag`, `image_digest`
- Vulnerability counts (`vuln_critical`, `vuln_high`, etc.) computed at ingest, stored as indexed columns
- Individual CVE rows written to a normalised `vulnerabilities` table for fast fleet-wide queries
- **Digest-based deduplication** — same `(image_name, image_digest)` updates in place instead of creating a new row; `200 OK` for upsert, `201 Created` for new rows

### Scan Querying
- `GET /scans?tag=<tag>` — Query all scans by image tag
- `GET /scans?image=<name>` — Query all scans by image name
- `GET /scans?image=<name>&severity=<level>` — Return only scans with at least one matching severity (uses pre-computed indexed columns — no JSONB scan)
- `GET /scans/all` — Global scan list with optional `image`, `tag`, `limit`, `offset` filters
- `GET /scans/{id}/vulnerabilities?severity=<level>&pkg=<name>` — Extract filtered vulnerabilities from one stored scan
- `GET /scans/latest?image=<name>` — Fetch the most recent scan for an image
- Optional pagination on all list endpoints via `limit` and `offset`

### Analytics (all deduplicated to latest scan per image:tag)
- `GET /analytics/vulnerabilities/summary` — Totals, severity breakdown, and **top 10 CVEs** inline
- `GET /analytics/vulnerabilities/trends` — Vulnerability counts bucketed by day or week
- `GET /analytics/vulnerabilities/top-cves` — Most common CVEs across the fleet, ordered by affected image count
- `GET /analytics/vulnerabilities/cve/:cve_id/images` — Which images are currently exposed to a specific CVE
- `GET /analytics/vulnerabilities/fixable` — Fixable vs non-fixable vulnerability counts with percentage

### Infrastructure
- `GET /health` — Health check
- Query-param fallback (`?image=&tag=`) when Trivy metadata is absent
- Struct-based config via [goconf](https://github.com/tlmanz/goconf) — prints a masked config table on startup
- Structured logging with [zerolog](https://github.com/rs/zerolog)
- Graceful shutdown
- Embedded [goose](https://github.com/pressly/goose) migrations — run automatically at startup
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

All three default to `0` / `1h`. Setting both `CLEANUP_MAX_AGE` and `CLEANUP_KEEP_PER_IMAGE` to zero disables the worker entirely — no background goroutine is spawned.

| Variable                 | Default   | Description                                 |
| ------------------------ | --------- | ------------------------------------------- |
| `CLEANUP_INTERVAL`       | `1h`      | How often the worker runs                   |
| `CLEANUP_MAX_AGE`        | `0` (off) | Delete scans older than this (e.g. `168h`)  |
| `CLEANUP_KEEP_PER_IMAGE` | `0` (off) | Keep only the N newest scans per image name |

---

## Cleanup Worker

A background goroutine runs on `CLEANUP_INTERVAL` and applies up to two retention policies. The worker only starts if at least one policy is non-zero.

When both policies are set, a scan must fail **both** to be deleted — per-image retention always wins over age:

| `CLEANUP_MAX_AGE` | `CLEANUP_KEEP_PER_IMAGE` | What gets deleted                                                                |
| ----------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `72h`             | off                      | Everything older than 72 h                                                       |
| off               | `10`                     | Every scan past the top 10 per image                                             |
| `72h`             | `10`                     | Only scans that are **both** older than 72 h **AND** ranked #11+ for their image |

> Vulnerability rows in the `vulnerabilities` table are automatically deleted via `ON DELETE CASCADE` when a scan is pruned — no extra cleanup logic needed.

---

## API Reference

### Endpoint Quick Map

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET`  | `/health` | Service health check |
| `POST` | `/scans` | Ingest one Trivy JSON report |
| `GET`  | `/scans?tag=<tag>` | List scans by image tag |
| `GET`  | `/scans?image=<name>[&severity=<level>]` | List scans by image name, optionally severity-filtered |
| `GET`  | `/scans/all[?image=&tag=&limit=&offset=]` | List scans globally with optional filters |
| `GET`  | `/scans/{id}/vulnerabilities[?severity=&pkg=]` | Extract vulnerabilities from one stored scan |
| `GET`  | `/scans/latest?image=<name>` | Fetch latest scan for an image |
| `GET`  | `/analytics/vulnerabilities/summary` | Totals, severity breakdown, top 10 CVEs |
| `GET`  | `/analytics/vulnerabilities/trends` | Bucketed vulnerability trend points |
| `GET`  | `/analytics/vulnerabilities/top-cves` | Top CVEs by number of affected images |
| `GET`  | `/analytics/vulnerabilities/cve/:cve_id/images` | Images currently exposed to a CVE |
| `GET`  | `/analytics/vulnerabilities/fixable` | Fixable vs non-fixable vuln counts |

---

### `POST /scans`

Ingest a raw Trivy JSON scan result. Metadata is auto-extracted from `ArtifactName` and `Metadata`; query params override.

**Deduplication:** if `image_digest` is non-empty and a row for that `(image_name, image_digest)` already exists, the row is updated in place and `200 OK` is returned. Empty digest (mutable tags like `latest`) always creates a new row.

| Query param | Description           |
| ----------- | --------------------- |
| `image`     | Override image name   |
| `tag`       | Override image tag    |
| `digest`    | Override image digest |

**`201 Created`** (new scan) or **`200 OK`** (digest upsert):

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "image_name": "nginx",
  "image_tag": "1.25",
  "image_digest": "sha256:abc123...",
  "scan_result": { "...": "..." },
  "created_at": "2026-04-20T14:35:00Z",
  "vuln_critical": 1,
  "vuln_high": 2,
  "vuln_medium": 3,
  "vuln_low": 0,
  "vuln_unknown": 0
}
```

---

### `GET /scans?tag=<tag>`

Optional pagination: `limit` (0–500), `offset` (≥ 0).

**`200 OK`** — `{ "tag": "1.25", "count": 2, "items": [...] }`

---

### `GET /scans?image=<name>[&severity=<level>]`

Severity filter uses pre-computed indexed columns — no JSONB scan. Valid values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.

**`200 OK`** — `{ "image": "nginx", "severity": "CRITICAL", "count": 1, "items": [...] }`

---

### `GET /analytics/vulnerabilities/summary`

Deduplicates to the **latest scan per `(image_name, image_tag)`** before aggregating — rescanning the same tag never inflates totals.

| Query param | Description |
| ----------- | ----------- |
| `image`     | Filter to one image (optional) |
| `from`, `to` | RFC 3339 time range (optional) |

**`200 OK`**

```json
{
  "image": "nginx",
  "total_scans": 3,
  "total_vulnerabilities": 47,
  "severity_counts": [
    { "severity": "CRITICAL", "count": 6 },
    { "severity": "HIGH",     "count": 19 }
  ],
  "top_cves": [
    { "cve_id": "CVE-2024-1234", "severity": "CRITICAL", "title": "...", "image_count": 3, "fixable": true }
  ]
}
```

---

### `GET /analytics/vulnerabilities/top-cves`

Returns the most common CVEs across the latest scan of each image:tag, ordered by number of distinct affected images.

| Query param | Description |
| ----------- | ----------- |
| `image`     | Filter to one image (optional) |
| `severity`  | Filter to one severity level (optional) |
| `limit`     | Max results, default 10, max 100 |
| `from`, `to` | RFC 3339 time range (optional) |

**`200 OK`**

```json
{
  "image": "",
  "severity": "",
  "limit": 10,
  "count": 2,
  "cves": [
    { "cve_id": "CVE-2024-1234", "severity": "CRITICAL", "title": "OpenSSL: ...", "image_count": 5, "fixable": true },
    { "cve_id": "CVE-2024-5678", "severity": "HIGH",     "title": "glibc: ...",   "image_count": 3, "fixable": false }
  ]
}
```

---

### `GET /analytics/vulnerabilities/cve/:cve_id/images`

Returns all images currently exposed to the given CVE ID, using the latest scan per `(image_name, image_tag)`.

**`200 OK`**

```json
{
  "cve_id": "CVE-2024-1234",
  "count": 2,
  "images": [
    {
      "image_name": "nginx",
      "image_tag": "1.25",
      "pkg_name": "openssl",
      "pkg_version": "3.0.2",
      "fixed_version": "3.0.3",
      "scanned_at": "2026-04-20T14:35:00Z"
    }
  ]
}
```

---

### `GET /analytics/vulnerabilities/fixable`

Returns fixable vs non-fixable vulnerability counts across the latest scan per image:tag,
plus the full list of fixable vulnerabilities ordered by severity (CRITICAL first) then CVE ID.

| Query param | Description |
| ----------- | ----------- |
| `image`     | Filter to one image (optional) |
| `from`, `to` | RFC 3339 time range (optional) |

**`200 OK`**

```json
{
  "image": "nginx",
  "total_vulns": 47,
  "fixable": 31,
  "not_fixable": 16,
  "fixable_pct": 65.96,
  "fixable_items": [
    {
      "cve_id": "CVE-2024-1234",
      "pkg_name": "openssl",
      "pkg_version": "3.0.2",
      "fixed_version": "3.0.3",
      "severity": "CRITICAL",
      "title": "OpenSSL: memory corruption in AES",
      "image_name": "nginx",
      "image_tag": "1.25"
    },
    {
      "cve_id": "CVE-2024-5678",
      "pkg_name": "busybox",
      "pkg_version": "1.35.0",
      "fixed_version": "1.36.0",
      "severity": "HIGH",
      "title": "busybox: command injection",
      "image_name": "nginx",
      "image_tag": "1.26"
    }
  ]
}
```

---

### `GET /analytics/vulnerabilities/trends`

Vulnerability counts bucketed by day or week, deduplicated to latest scan per tag per bucket.

| Query param | Description |
| ----------- | ----------- |
| `image`     | Filter to one image (optional) |
| `interval`  | `day` or `week` (default: `day`) |
| `from`, `to` | RFC 3339 time range (optional) |

**`200 OK`**

```json
{
  "image": "nginx",
  "interval": "day",
  "count": 2,
  "points": [
    { "bucket": "2026-04-20T00:00:00Z", "severity": "CRITICAL", "count": 2 },
    { "bucket": "2026-04-21T00:00:00Z", "severity": "HIGH",     "count": 3 }
  ]
}
```

---

### `GET /scans/{id}/vulnerabilities`

Extracts vulnerabilities from the stored JSONB blob for a specific scan. Both filters are optional and case-insensitive.

| Query param | Description |
| ----------- | ----------- |
| `severity`  | Filter by severity (optional) |
| `pkg`       | Filter by package name (optional) |

**`200 OK`** — `{ "scan_id": "...", "count": 1, "items": [...] }`  
**`404 Not Found`** — scan ID does not exist

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
      "ImageID": "sha256:abc123",
      "RepoTags": ["nginx:1.25"],
      "RepoDigests": ["nginx@sha256:def456"]
    },
    "Results": [{"Target": "nginx:1.25", "Class": "os-pkgs", "Vulnerabilities": [
      {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","FixedVersion":"3.0.3","Severity":"CRITICAL","Title":"OpenSSL bug"}
    ]}]
  }' | jq .

# Query by image + severity (uses indexed column, fast)
curl -s "http://localhost:8080/scans?image=nginx&severity=CRITICAL" | jq .

# Vulnerability summary with top CVEs
curl -s "http://localhost:8080/analytics/vulnerabilities/summary?image=nginx" | jq .

# Top 20 CVEs across the entire fleet
curl -s "http://localhost:8080/analytics/vulnerabilities/top-cves?limit=20" | jq .

# Which images are affected by a specific CVE?
curl -s "http://localhost:8080/analytics/vulnerabilities/cve/CVE-2026-0001/images" | jq .

# How many vulns have a fix available?
curl -s "http://localhost:8080/analytics/vulnerabilities/fixable?image=nginx" | jq .

# Vulnerability trends by day
curl -s "http://localhost:8080/analytics/vulnerabilities/trends?image=nginx&interval=day" | jq .

# Latest scan for an image
curl -s "http://localhost:8080/scans/latest?image=nginx" | jq .

# Extract filtered vulnerabilities from a specific scan
curl -s "http://localhost:8080/scans/<scan-id>/vulnerabilities?severity=HIGH&pkg=openssl" | jq .
```

---

## Tests

```bash
# Unit tests (no Docker required)
go test -race ./internal/parser/... ./internal/config/... ./internal/handlers/...

# Integration tests (requires Docker — spins up a real Postgres via testcontainers)
go test -race -v ./internal/repository/...

# Everything
make test
```

Test coverage:

- **Parser** — metadata extraction, tag splitting, digest fallback, vuln extraction, invalid JSON
- **Config** — defaults, env overrides, validation errors
- **Handlers** — all endpoints via `httptest` + in-memory mock store
- **Repository** — integration tests against a real Postgres container (including digest deduplication, vuln counts, analytics)

---

## Project Structure

```
scanvault/
├── models/
│   ├── scan.go                     # Scan, VulnCounts, VulnerabilitySummary types
│   └── vulnerability.go            # Vulnerability, TopCVE, AffectedImage, FixableSummary
├── cmd/server/main.go              # Thin CLI entrypoint
├── internal/
│   ├── config/config.go            # goconf env-based config
│   ├── db/db.go                    # pgx/v5 connection pool
│   ├── handlers/scan_handler.go    # HTTP handlers (uses Store interface)
│   ├── parser/trivy.go             # Trivy JSON parser (meta + vuln extraction)
│   ├── repository/scan_repo.go     # PostgreSQL queries + analytics + cleanup
│   ├── service/server.go           # Service bootstrap + lifecycle
│   ├── service/migrate.go          # Embedded goose migration runner
│   ├── service/logger.go           # Logger setup from config
│   └── worker/cleanup.go           # Background cleanup worker
├── migrations/
│   ├── 001_create_scans.sql        # Base scans table
│   ├── 002_add_scan_result_gin_index.sql  # GIN index on scan_result
│   ├── 003_add_vuln_summary.sql    # vuln_* count columns + partial indexes
│   ├── 004_upsert_digest_index.sql # Unique partial index for digest dedup
│   ├── 005_create_vulnerabilities.sql    # Normalised vulnerabilities table
│   └── embed.go                    # //go:embed *.sql
├── postman/
│   └── ScanVault.postman_collection.json
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Database Schema

```sql
-- Core scan records
CREATE TABLE scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name    TEXT        NOT NULL,
    image_tag     TEXT        NOT NULL DEFAULT '',
    image_digest  TEXT        NOT NULL DEFAULT '',
    scan_result   JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Pre-computed at ingest for fast indexed filtering
    vuln_critical INT         NOT NULL DEFAULT 0,
    vuln_high     INT         NOT NULL DEFAULT 0,
    vuln_medium   INT         NOT NULL DEFAULT 0,
    vuln_low      INT         NOT NULL DEFAULT 0,
    vuln_unknown  INT         NOT NULL DEFAULT 0
);

-- Digest dedup: one row per (image_name, image_digest) when digest is non-empty
CREATE UNIQUE INDEX idx_scans_image_digest_unique ON scans(image_name, image_digest)
    WHERE image_digest != '';

-- Normalised vulnerability rows (populated atomically with each scan upsert)
CREATE TABLE vulnerabilities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id        TEXT NOT NULL,
    pkg_name      TEXT NOT NULL,
    pkg_version   TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    UNIQUE (scan_id, cve_id, pkg_name)
);
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
