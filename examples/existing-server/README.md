# Existing Server Example

This example shows how to embed ScanVault into an existing `net/http` application.

It demonstrates:
- Mounting ScanVault under a route prefix (`/trivy/*`)
- Keeping your own app routes and middleware
- Passing an existing `*pgxpool.Pool` via `scanvault.WithDBPool(pool)`
- Graceful shutdown with signals

## Run

From the repository root:

```bash
export DATABASE_URL='postgres://scanvault:scanvault@localhost:5432/scanvault?sslmode=disable'
go run ./examples/existing-server
```

Then test:

```bash
curl -s http://localhost:9000/healthz
curl -s http://localhost:9000/trivy/health
```

## Notes

- ScanVault migrations run on startup using the provided pool.
- The example owns the pool lifecycle (`pool.Close()`).
- `scanvault.Server.Close()` is still called for internal cleanup.