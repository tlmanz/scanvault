package repository_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tlmanz/scanvault/internal/repository"
	svmigrations "github.com/tlmanz/scanvault/migrations"

	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// setupDB starts a Postgres container, runs goose migrations, and returns a
// pool connected to it. The container is terminated when the test ends.
func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}
	t.Cleanup(func() { pgContainer.Terminate(ctx) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting connection string: %v", err)
	}

	// Run migrations via goose with the embedded FS.
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("opening sql.DB: %v", err)
	}
	defer sqlDB.Close()

	goose.SetBaseFS(svmigrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting goose dialect: %v", err)
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		t.Fatalf("running migrations: %v", err)
	}

	// Open a pgx pool for the test.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("creating pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestCreate_And_LatestByImage(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"ArtifactName":"nginx:1.25","Results":[]}`)

	created, err := repo.Create(ctx, "nginx", "1.25", "sha256:abc", raw)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
	if created.ImageName != "nginx" {
		t.Errorf("ImageName: want nginx, got %s", created.ImageName)
	}
	if created.ImageTag != "1.25" {
		t.Errorf("ImageTag: want 1.25, got %s", created.ImageTag)
	}

	latest, err := repo.LatestByImage(ctx, "nginx")
	if err != nil {
		t.Fatalf("LatestByImage: %v", err)
	}
	if latest == nil {
		t.Fatal("expected a scan, got nil")
	}
	if latest.ID != created.ID {
		t.Errorf("ID mismatch: want %s, got %s", created.ID, latest.ID)
	}
}

func TestLatestByImage_NotFound(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)

	scan, err := repo.LatestByImage(context.Background(), "ghost-image")
	if err != nil {
		t.Fatalf("LatestByImage: %v", err)
	}
	if scan != nil {
		t.Errorf("expected nil scan for unknown image, got %+v", scan)
	}
}

func TestListByTag(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)

	// Insert two scans for the same tag, one for a different tag.
	if _, err := repo.Create(ctx, "nginx", "1.25", "", raw); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := repo.Create(ctx, "nginx", "1.25", "", raw); err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	if _, err := repo.Create(ctx, "alpine", "3.19", "", raw); err != nil {
		t.Fatalf("Create 3: %v", err)
	}

	scans, err := repo.ListByTag(ctx, "1.25")
	if err != nil {
		t.Fatalf("ListByTag: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("want 2 scans for tag 1.25, got %d", len(scans))
	}

	// Verify ordering (newest first).
	if len(scans) == 2 && scans[0].CreatedAt.Before(scans[1].CreatedAt) {
		t.Error("scans not ordered newest first")
	}
}

func TestListByTag_EmptyResult(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)

	scans, err := repo.ListByTag(context.Background(), "nonexistent-tag")
	if err != nil {
		t.Fatalf("ListByTag: %v", err)
	}
	if scans == nil {
		t.Error("expected empty slice, got nil")
	}
	if len(scans) != 0 {
		t.Errorf("expected 0 scans, got %d", len(scans))
	}
}

func TestLatestByImage_ReturnsNewest(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)

	first, err := repo.Create(ctx, "nginx", "1.24", "", raw)
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, err := repo.Create(ctx, "nginx", "1.25", "", raw)
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}

	latest, err := repo.LatestByImage(ctx, "nginx")
	if err != nil {
		t.Fatalf("LatestByImage: %v", err)
	}
	if latest.ID != second.ID {
		t.Errorf("want latest ID %s, got %s (first was %s)", second.ID, latest.ID, first.ID)
	}
}

func TestGetByID(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)
	created, err := repo.Create(ctx, "nginx", "1.25", "", raw)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected scan, got nil")
	}
	if got.ID != created.ID {
		t.Errorf("ID mismatch: want %s, got %s", created.ID, got.ID)
	}
}

func TestListByImageWithSeverity(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	critical := json.RawMessage(`{
		"Results":[
			{"Target":"img","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"CRITICAL","PkgName":"openssl"}]}
		]
	}`)
	low := json.RawMessage(`{
		"Results":[
			{"Target":"img","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"busybox"}]}
		]
	}`)

	if _, err := repo.Create(ctx, "nginx", "1.25", "", critical); err != nil {
		t.Fatalf("Create critical: %v", err)
	}
	if _, err := repo.Create(ctx, "nginx", "1.26", "", low); err != nil {
		t.Fatalf("Create low: %v", err)
	}
	if _, err := repo.Create(ctx, "alpine", "3.19", "", critical); err != nil {
		t.Fatalf("Create other image: %v", err)
	}

	matches, err := repo.ListByImageWithSeverity(ctx, "nginx", "critical")
	if err != nil {
		t.Fatalf("ListByImageWithSeverity: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	if matches[0].ImageName != "nginx" {
		t.Errorf("ImageName: want nginx, got %s", matches[0].ImageName)
	}
}

func TestListByImageWithSeverity_MalformedResultsDoesNotError(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	if _, err := repo.Create(ctx, "nginx", "1.0", "", json.RawMessage(`{"Results":{}}`)); err != nil {
		t.Fatalf("Create malformed: %v", err)
	}
	if _, err := repo.Create(ctx, "nginx", "1.1", "", json.RawMessage(`{"Results":[{"Vulnerabilities":[{"Severity":"HIGH"}]}]}`)); err != nil {
		t.Fatalf("Create valid: %v", err)
	}

	matches, err := repo.ListByImageWithSeverity(ctx, "nginx", "HIGH")
	if err != nil {
		t.Fatalf("ListByImageWithSeverity: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
}

func TestListByTagPage(t *testing.T) {
	pool := setupDB(t)
	repo := repository.New(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)
	for i := 0; i < 3; i++ {
		if _, err := repo.Create(ctx, "nginx", "1.25", "", raw); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	items, err := repo.ListByTagPage(ctx, "1.25", 2, 1)
	if err != nil {
		t.Fatalf("ListByTagPage: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
}
