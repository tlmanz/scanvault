package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	pgcontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tlmanz/scanvault/domain/entities"
	"github.com/tlmanz/scanvault/domain/parser"
	svmigrations "github.com/tlmanz/scanvault/migrations"
	"github.com/tlmanz/scanvault/persistence/postgres"

	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// setupDB starts a Postgres container, runs goose migrations, and returns a
// pool connected to it. The container is terminated when the test ends.
func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := pgcontainer.Run(ctx,
		"postgres:16-alpine",
		pgcontainer.WithDatabase("testdb"),
		pgcontainer.WithUsername("testuser"),
		pgcontainer.WithPassword("testpass"),
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

// mustCreate is a test helper that inserts a scan, computing vuln counts and
// extracting vulnerabilities from the raw JSON (mirrors what the real handler does).
func mustCreate(t *testing.T, repo *postgres.ScanRepository, ctx context.Context, image, tag, digest string, raw json.RawMessage) *entities.Scan {
	t.Helper()
	counts := parser.CountVulnerabilities(raw)
	vulns := parser.ExtractVulnerabilities(raw)
	scan, _, err := repo.Create(ctx, image, tag, digest, raw, counts, vulns)
	if err != nil {
		t.Fatalf("Create(%s:%s): %v", image, tag, err)
	}
	return scan
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestCreate_And_LatestByImage(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"ArtifactName":"nginx:1.25","Results":[]}`)

	created := mustCreate(t, repo, ctx, "nginx", "1.25", "sha256:abc", raw)
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
	repo := postgres.NewScanRepository(pool)

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
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)

	// Insert two scans for the same tag, one for a different tag.
	mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)
	mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)
	mustCreate(t, repo, ctx, "alpine", "3.19", "", raw)

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
	repo := postgres.NewScanRepository(pool)

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
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)

	first := mustCreate(t, repo, ctx, "nginx", "1.24", "", raw)
	second := mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)

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
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)
	created := mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)

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

func TestCreate_VulnCountsPopulated(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{
		"Results":[
			{"Vulnerabilities":[
				{"Severity":"CRITICAL","PkgName":"openssl"},
				{"Severity":"CRITICAL","PkgName":"libssl"},
				{"Severity":"HIGH","PkgName":"glibc"},
				{"Severity":"LOW","PkgName":"busybox"}
			]}
		]
	}`)

	scan := mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)

	if scan.VulnCritical != 2 {
		t.Errorf("VulnCritical: want 2, got %d", scan.VulnCritical)
	}
	if scan.VulnHigh != 1 {
		t.Errorf("VulnHigh: want 1, got %d", scan.VulnHigh)
	}
	if scan.VulnLow != 1 {
		t.Errorf("VulnLow: want 1, got %d", scan.VulnLow)
	}
	if scan.VulnMedium != 0 {
		t.Errorf("VulnMedium: want 0, got %d", scan.VulnMedium)
	}
}

func TestListByImageWithSeverity(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
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

	mustCreate(t, repo, ctx, "nginx", "1.25", "", critical)
	mustCreate(t, repo, ctx, "nginx", "1.26", "", low)
	mustCreate(t, repo, ctx, "alpine", "3.19", "", critical)

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
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	// malformed Results (object instead of array) — vuln count will be 0, no match
	mustCreate(t, repo, ctx, "nginx", "1.0", "", json.RawMessage(`{"Results":{}}`))
	// valid HIGH vuln — count = 1
	mustCreate(t, repo, ctx, "nginx", "1.1", "", json.RawMessage(`{"Results":[{"Vulnerabilities":[{"Severity":"HIGH"}]}]}`))

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
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)
	for i := 0; i < 3; i++ {
		mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)
	}

	items, err := repo.ListByTagPage(ctx, "1.25", 2, 1)
	if err != nil {
		t.Fatalf("ListByTagPage: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
}

func TestListAllPage_WithPagination(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{"Results":[]}`)
	first := mustCreate(t, repo, ctx, "nginx", "1.24", "", raw)
	second := mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)
	third := mustCreate(t, repo, ctx, "alpine", "3.19", "", raw)

	base := time.Now().UTC()
	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at=$1 WHERE id=$2`, base.Add(-3*time.Hour), first.ID); err != nil {
		t.Fatalf("update first created_at: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at=$1 WHERE id=$2`, base.Add(-2*time.Hour), second.ID); err != nil {
		t.Fatalf("update second created_at: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at=$1 WHERE id=$2`, base.Add(-1*time.Hour), third.ID); err != nil {
		t.Fatalf("update third created_at: %v", err)
	}

	items, err := repo.ListAllPage(ctx, "", "", 2, 1)
	if err != nil {
		t.Fatalf("ListAllPage: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
	if items[0].ID != second.ID || items[1].ID != first.ID {
		t.Fatalf("unexpected order: got [%s, %s], want [%s, %s]", items[0].ID, items[1].ID, second.ID, first.ID)
	}
}

func TestVulnerabilitySummary_ByImage(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	scanA := json.RawMessage(`{
		"Results":[
			{"Vulnerabilities":[
				{"Severity":"CRITICAL","PkgName":"openssl"},
				{"Severity":"HIGH","PkgName":"glibc"}
			]}
		]
	}`)
	scanB := json.RawMessage(`{
		"Results":[
			{"Vulnerabilities":[
				{"Severity":"LOW","PkgName":"busybox"}
			]}
		]
	}`)

	mustCreate(t, repo, ctx, "nginx", "1.25", "", scanA)
	mustCreate(t, repo, ctx, "nginx", "1.26", "", scanB)
	mustCreate(t, repo, ctx, "alpine", "3.19", "", scanA)

	summary, err := repo.VulnerabilitySummary(ctx, "nginx", nil, nil)
	if err != nil {
		t.Fatalf("VulnerabilitySummary: %v", err)
	}

	if summary.TotalScans != 2 {
		t.Fatalf("total_scans: want 2, got %d", summary.TotalScans)
	}
	if summary.TotalVulnerabilities != 3 {
		t.Fatalf("total_vulnerabilities: want 3, got %d", summary.TotalVulnerabilities)
	}

	counts := map[string]int64{}
	for _, item := range summary.SeverityCounts {
		counts[item.Severity] = item.Count
	}
	if counts["CRITICAL"] != 1 || counts["HIGH"] != 1 || counts["LOW"] != 1 {
		t.Fatalf("unexpected severity counts: %+v", counts)
	}
}

func TestVulnerabilityTrends_ByDay(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)
	ctx := context.Background()

	raw := json.RawMessage(`{
		"Results":[
			{"Vulnerabilities":[{"Severity":"CRITICAL","PkgName":"openssl"}]}
		]
	}`)

	first := mustCreate(t, repo, ctx, "nginx", "1.25", "", raw)
	second := mustCreate(t, repo, ctx, "nginx", "1.26", "", raw)

	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at=$1 WHERE id=$2`, time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC), first.ID); err != nil {
		t.Fatalf("update first created_at: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at=$1 WHERE id=$2`, time.Date(2026, 4, 21, 11, 0, 0, 0, time.UTC), second.ID); err != nil {
		t.Fatalf("update second created_at: %v", err)
	}

	points, err := repo.VulnerabilityTrends(ctx, "nginx", "day", nil, nil)
	if err != nil {
		t.Fatalf("VulnerabilityTrends: %v", err)
	}

	if len(points) != 2 {
		t.Fatalf("want 2 trend points, got %d", len(points))
	}

	got := map[string]int64{}
	for _, p := range points {
		key := p.Bucket.Format("2006-01-02")
		got[key] += p.Count
	}
	if got["2026-04-20"] != 1 || got["2026-04-21"] != 1 {
		t.Fatalf("unexpected trend counts: %+v", got)
	}
}

func TestVulnerabilityTrends_InvalidBucket(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.NewScanRepository(pool)

	_, err := repo.VulnerabilityTrends(context.Background(), "nginx", "month", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid bucket, got nil")
	}
}
