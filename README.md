[![CI](https://github.com/tlmanz/scanvault/actions/workflows/ci.yml/badge.svg)](https://github.com/tlmanz/scanvault/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tlmanz/scanvault/actions/workflows/codequality.yml/badge.svg)](https://github.com/tlmanz/scanvault/actions/workflows/codequality.yml)
[![Coverage Status](https://coveralls.io/repos/github/tlmanz/scanvault/badge.svg)](https://coveralls.io/github/tlmanz/scanvault)
![Open Issues](https://img.shields.io/github/issues/tlmanz/scanvault)
[![Go Report Card](https://goreportcard.com/badge/github.com/tlmanz/scanvault)](https://goreportcard.com/report/github.com/tlmanz/scanvault)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/tlmanz/scanvault)

# ScanVault

ScanVault is a production-ready Go microservice that ingests [Trivy](https://github.com/aquasecurity/trivy) container image scan results and stores them in PostgreSQL for fast querying, deduplication, and vulnerability analytics.

## Table of Contents

- [Why ScanVault](#why-scanvault)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [API Overview](#api-overview)
- [OpenAPI Docs](#openapi-docs)
- [Configuration](#configuration)
- [Cleanup Worker](#cleanup-worker)
- [Development](#development)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Tech Stack](#tech-stack)

## Why ScanVault

- Stores Trivy scan JSON in PostgreSQL with image metadata extracted at ingest time.
- Avoids duplicate scan rows for immutable digests via `(image_name, image_digest)` upsert.
- Persists normalized CVE rows for fast fleet-level analytics.
- Exposes pragmatic HTTP APIs for ingest, querying, and trends.

## Key Features

### Scan Ingestion

- `POST /scans` to ingest raw Trivy JSON.
- Automatically extracts `image_name`, `image_tag`, and `image_digest`.
- Computes and stores `vuln_critical`, `vuln_high`, `vuln_medium`, `vuln_low`, `vuln_unknown`.
- Writes normalized vulnerabilities into a catalog (`vulnerabilities`) and links them via `scan_vulnerabilities`.

### Querying and Analytics

- Query scans by image, tag, and optional severity.
- Fetch latest scan per image.
- Extract filtered vulnerabilities from a specific scan.
- Response payloads for scan data follow Trivy-style field names, including nested vulnerability details.
- Summary, trends, top CVEs, CVE-affected images, and fixable vulnerability analytics.

### Runtime and Operations

- `GET /health` health endpoint.
- Graceful shutdown.
- Embedded goose migrations run automatically at startup.
- Optional cleanup worker for retention.
- Structured logging with `zerolog`.

## Quick Start

### Prerequisites

| Tool                                                    | Version |
| ------------------------------------------------------- | ------- |
| [Go](https://go.dev/dl/)                                | 1.22+   |
| [Docker](https://docs.docker.com/get-docker/) + Compose | recent  |

### Run with Docker Compose (recommended)

```bash
git clone <repo-url>
cd scanvault
make env-copy
make docker-up
```

Service is available at `http://localhost:8080`.

### Run locally with `go run`

```bash
# 1) Start PostgreSQL
docker run -d --name pg \
  -e POSTGRES_DB=scanvault \
  -e POSTGRES_USER=scanvault \
  -e POSTGRES_PASSWORD=scanvault \
  -p 5432:5432 postgres:16-alpine

# 2) Create .env from example
make env-copy

# 3) Start service
make run
```

## API Overview

## OpenAPI Docs

- Swagger UI: `GET /swagger`
- OpenAPI JSON (auto-generated): `GET /swagger/openapi.json`
- The Swagger UI is generated from the REST route metadata and reflects the current request/response contracts.

### Endpoints

| Method | Path                                            | Purpose                                      |
| ------ | ----------------------------------------------- | -------------------------------------------- |
| `GET`  | `/health`                                       | Service health check                         |
| `POST` | `/scans`                                        | Ingest one Trivy JSON report                 |
| `GET`  | `/scans?tag=<tag>`                              | List scans by image tag                      |
| `GET`  | `/scans?image=<name>[&severity=<level>]`        | List scans by image name                     |
| `GET`  | `/scans/all[?image=&tag=&limit=&offset=]`       | Global scan list with optional filters       |
| `GET`  | `/scans/{id}/vulnerabilities[?severity=&pkg=]`  | Vulnerabilities from one stored scan         |
| `GET`  | `/scans/latest?image=<name>`                    | Most recent scan for an image                |
| `GET`  | `/analytics/vulnerabilities/summary`            | Totals, severity breakdown, top CVEs         |
| `GET`  | `/analytics/vulnerabilities/trends`             | Day/week vulnerability trend points          |
| `GET`  | `/analytics/vulnerabilities/top-cves`           | Top CVEs by affected image count             |
| `GET`  | `/analytics/vulnerabilities/cve/:cve_id/images` | Images currently exposed to a CVE            |
| `GET`  | `/analytics/vulnerabilities/fixable`            | Fixable vs non-fixable vulnerability summary |

### Ingest Behavior

- `POST /scans` supports query param overrides: `image`, `tag`, `digest`.
- If digest is present and `(image_name, image_digest)` already exists, ScanVault updates in place and returns `200 OK`.
- If digest is empty, ScanVault creates a new row and returns `201 Created`.

### Sample `curl` Commands

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

# Query by image + severity
curl -s "http://localhost:8080/scans?image=nginx&severity=CRITICAL" | jq .

# Summary and top CVEs
curl -s "http://localhost:8080/analytics/vulnerabilities/summary?image=nginx" | jq .

# Top CVEs across fleet
curl -s "http://localhost:8080/analytics/vulnerabilities/top-cves?limit=20" | jq .

# Images affected by one CVE
curl -s "http://localhost:8080/analytics/vulnerabilities/cve/CVE-2026-0001/images" | jq .

# Fixable vulnerability summary
curl -s "http://localhost:8080/analytics/vulnerabilities/fixable?image=nginx" | jq .

# Vulnerability trends by day
curl -s "http://localhost:8080/analytics/vulnerabilities/trends?image=nginx&interval=day" | jq .

# Latest scan for an image
curl -s "http://localhost:8080/scans/latest?image=nginx" | jq .

# Vulnerabilities for one scan
curl -s "http://localhost:8080/scans/<scan-id>/vulnerabilities?severity=HIGH&pkg=openssl" | jq .
```

## Configuration

Configuration is loaded from env vars (or `.env`) using [goconf](https://github.com/tlmanz/goconf), and a masked configuration table is printed on startup.

### Required

| Variable       | Description    |
| -------------- | -------------- |
| `DATABASE_URL` | PostgreSQL DSN |

### HTTP Server

| Variable             | Default | Description                      |
| -------------------- | ------- | -------------------------------- |
| `SERVER_PORT`        | `8080`  | Listen port                      |
| `LOG_LEVEL`          | `info`  | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT`         | `json`  | `json` or `console`              |
| `HTTP_READ_TIMEOUT`  | `15s`   | Request read timeout             |
| `HTTP_WRITE_TIMEOUT` | `15s`   | Response write timeout           |
| `HTTP_IDLE_TIMEOUT`  | `60s`   | Keep-alive idle timeout          |

### Database Pool

| Variable                 | Default | Description                |
| ------------------------ | ------- | -------------------------- |
| `DB_MAX_CONNS`           | `25`    | Max open connections       |
| `DB_MIN_CONNS`           | `2`     | Min idle connections       |
| `DB_MAX_CONN_LIFETIME`   | `30m`   | Max connection lifetime    |
| `DB_MAX_CONN_IDLE_TIME`  | `5m`    | Max idle time              |
| `DB_HEALTH_CHECK_PERIOD` | `1m`    | Pool health-check interval |

### Cleanup Worker

All cleanup settings are optional.

| Variable                 | Default | Description                           |
| ------------------------ | ------- | ------------------------------------- |
| `CLEANUP_INTERVAL`       | `1h`    | Worker run interval                   |
| `CLEANUP_MAX_AGE`        | `0`     | Delete scans older than this duration |
| `CLEANUP_KEEP_PER_IMAGE` | `0`     | Keep only newest N scans per image    |

If both `CLEANUP_MAX_AGE` and `CLEANUP_KEEP_PER_IMAGE` are `0`, cleanup is disabled.

## Cleanup Worker

The worker applies up to two retention policies. When both are set, a scan is deleted only if it is both older than `CLEANUP_MAX_AGE` and outside the newest `CLEANUP_KEEP_PER_IMAGE` for that image.

| `CLEANUP_MAX_AGE` | `CLEANUP_KEEP_PER_IMAGE` | Result                                  |
| ----------------- | ------------------------ | --------------------------------------- |
| `72h`             | off                      | Delete scans older than 72 hours        |
| off               | `10`                     | Keep latest 10 scans per image          |
| `72h`             | `10`                     | Delete only scans that match both rules |

`scan_vulnerabilities` rows are deleted automatically with their parent scan via `ON DELETE CASCADE`.

## Development

### Common Make Targets

```bash
make help
make run
make build
make run-binary
make test
make openapi
make lint
make vet
make fmt
make docker-up
make docker-down
make docker-logs
```

### Migration Targets

```bash
make migrate
make migrate-status
make migrate-down
make migrate-dry
```

## Testing

```bash
# Unit tests
go test -race ./domain/... ./infra/... ./presentation/...

# Integration tests (Docker required)
go test -race -v ./persistence/...

# Full suite
make test
```

Coverage focus:

- Parser behavior and metadata extraction.
- Config defaults, overrides, and validation.
- Handler endpoint behavior with mocks.
- Repository queries and analytics with real PostgreSQL via testcontainers.

## Project Structure

```text
scanvault/
├── main.go                         # Executable entrypoint
├── domain/                         # Core business logic and entities
│   ├── boundary/                   # Interfaces defining infrastructure contracts
│   ├── entities/                   # Domain models
│   ├── parser/                     # Pure logic for Trivy parsing
│   └── usecases/                   # Application-specific business rules
├── infra/                          # Cross-cutting concerns
│   ├── config.go                   # Environment configuration
│   ├── container.go                # IoC container and dependency wiring
│   ├── lifecycle.go                # Graceful shutdown handler
│   └── logger.go                   # Logger initialization
├── persistence/postgres/           # Database implementations
│   ├── db.go                       # Connection pooling
│   ├── migrate.go                  # Embedded Goose migrations
│   └── scan_repository.go          # Implements domain/boundary interfaces
├── presentation/rest/              # HTTP delivery mechanisms
│   ├── controller_analytics.go     # Analytics endpoints
│   ├── controller_scan.go          # CRUD endpoints
│   ├── requests.go                 # DTO definitions
│   ├── responses.go                # DTO definitions
│   ├── routes.go                   # OpenAPI route registration
│   └── server.go                   # HTTP server lifecycle
├── migrations/                     # Raw SQL migration files
├── postman/ScanVault.postman_collection.json
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── .env.example
```

## Database Schema

```sql
CREATE TABLE scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name    TEXT        NOT NULL,
    image_tag     TEXT        NOT NULL DEFAULT '',
    image_digest  TEXT        NOT NULL DEFAULT '',
    scan_result   JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    vuln_critical INT         NOT NULL DEFAULT 0,
    vuln_high     INT         NOT NULL DEFAULT 0,
    vuln_medium   INT         NOT NULL DEFAULT 0,
    vuln_low      INT         NOT NULL DEFAULT 0,
    vuln_unknown  INT         NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_scans_image_digest_unique ON scans(image_name, image_digest)
    WHERE image_digest != '';

CREATE TABLE vulnerabilities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id      TEXT NOT NULL,
    pkg_name    TEXT NOT NULL,
    pkg_version TEXT NOT NULL DEFAULT '',
    UNIQUE (cve_id, pkg_name, pkg_version)
);

CREATE TABLE scan_vulnerabilities (
    scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    severity         TEXT NOT NULL,
    fixed_version    TEXT NOT NULL DEFAULT '',
    title            TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, vulnerability_id)
);
```

## Tech Stack

| Layer      | Library                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------- |
| HTTP       | [Gin](https://github.com/gin-gonic/gin)                                                      |
| Database   | [pgx/v5](https://github.com/jackc/pgx)                                                       |
| Migrations | [goose/v3](https://github.com/pressly/goose)                                                 |
| Config     | [goconf](https://github.com/tlmanz/goconf) + [caarlos0/env](https://github.com/caarlos0/env) |
| Logging    | [zerolog](https://github.com/rs/zerolog)                                                     |
| Tests      | [testcontainers-go](https://github.com/testcontainers/testcontainers-go)                     |
| Runtime    | [distroless/static](https://github.com/GoogleContainerTools/distroless)                      |
