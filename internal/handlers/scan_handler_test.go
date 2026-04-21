package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/internal/handlers"
	"github.com/tlmanz/scanvault/models"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ── Mock Store ────────────────────────────────────────────────────────────────

type mockStore struct {
	createFn              func(ctx context.Context, name, tag, digest string, result json.RawMessage, vuln models.VulnCounts, vulns []models.Vulnerability) (*models.Scan, bool, error)
	listByTagFn           func(ctx context.Context, tag string) ([]models.Scan, error)
	listByImageFn         func(ctx context.Context, image string) ([]models.Scan, error)
	listByImageSeverityFn func(ctx context.Context, image, severity string) ([]models.Scan, error)
	listAllPageFn         func(ctx context.Context, image, tag string, limit, offset int) ([]models.Scan, error)
	vulnerabilitySummary  func(ctx context.Context, image string, from, to *time.Time) (*models.VulnerabilitySummary, error)
	vulnerabilityTrends   func(ctx context.Context, image, interval string, from, to *time.Time) ([]models.VulnerabilityTrendPoint, error)
	latestByImgFn         func(ctx context.Context, image string) (*models.Scan, error)
	getByIDFn             func(ctx context.Context, id string) (*models.Scan, error)
}

func (m *mockStore) Create(ctx context.Context, name, tag, digest string, result json.RawMessage, vuln models.VulnCounts, vulns []models.Vulnerability) (*models.Scan, bool, error) {
	if m.createFn != nil {
		return m.createFn(ctx, name, tag, digest, result, vuln, vulns)
	}
	return &models.Scan{ID: "test-id", ImageName: name, ImageTag: tag, ImageDigest: digest, ScanResult: result, CreatedAt: time.Now()}, true, nil
}

func (m *mockStore) TopCVEs(_ context.Context, _, _ string, _ int, _, _ *time.Time) ([]models.TopCVE, error) {
	return []models.TopCVE{}, nil
}
func (m *mockStore) CVEAffectedImages(_ context.Context, _ string) ([]models.AffectedImage, error) {
	return []models.AffectedImage{}, nil
}
func (m *mockStore) FixableSummary(_ context.Context, _ string, _, _ *time.Time) (*models.FixableSummary, error) {
	return &models.FixableSummary{FixableItems: []models.FixableVulnerability{}}, nil
}

func (m *mockStore) ListByTag(ctx context.Context, tag string) ([]models.Scan, error) {
	if m.listByTagFn != nil {
		return m.listByTagFn(ctx, tag)
	}
	return []models.Scan{}, nil
}

func (m *mockStore) LatestByImage(ctx context.Context, image string) (*models.Scan, error) {
	if m.latestByImgFn != nil {
		return m.latestByImgFn(ctx, image)
	}
	return nil, nil
}

func (m *mockStore) ListByImage(ctx context.Context, image string) ([]models.Scan, error) {
	if m.listByImageFn != nil {
		return m.listByImageFn(ctx, image)
	}
	return []models.Scan{}, nil
}

func (m *mockStore) ListByImageWithSeverity(ctx context.Context, image, severity string) ([]models.Scan, error) {
	if m.listByImageSeverityFn != nil {
		return m.listByImageSeverityFn(ctx, image, severity)
	}
	return []models.Scan{}, nil
}

func (m *mockStore) ListAllPage(ctx context.Context, image, tag string, limit, offset int) ([]models.Scan, error) {
	if m.listAllPageFn != nil {
		return m.listAllPageFn(ctx, image, tag, limit, offset)
	}
	return []models.Scan{}, nil
}

func (m *mockStore) VulnerabilitySummary(ctx context.Context, image string, from, to *time.Time) (*models.VulnerabilitySummary, error) {
	if m.vulnerabilitySummary != nil {
		return m.vulnerabilitySummary(ctx, image, from, to)
	}
	return &models.VulnerabilitySummary{SeverityCounts: []models.SeverityCount{}}, nil
}

func (m *mockStore) VulnerabilityTrends(ctx context.Context, image, interval string, from, to *time.Time) ([]models.VulnerabilityTrendPoint, error) {
	if m.vulnerabilityTrends != nil {
		return m.vulnerabilityTrends(ctx, image, interval, from, to)
	}
	return []models.VulnerabilityTrendPoint{}, nil
}

func (m *mockStore) GetByID(ctx context.Context, id string) (*models.Scan, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newRouter(store handlers.Store) *gin.Engine {
	h := handlers.New(store, zerolog.Nop())
	r := gin.New()
	r.GET("/health", h.HealthCheck)
	r.POST("/scans", h.CreateScan)
	r.GET("/scans", h.ListScans)
	r.GET("/scans/all", h.ListAllScans)
	r.GET("/scans/:id/vulnerabilities", h.GetScanVulnerabilities)
	r.GET("/scans/latest", h.GetLatestScan)
	r.GET("/analytics/vulnerabilities/summary", h.GetVulnerabilitySummary)
	r.GET("/analytics/vulnerabilities/trends", h.GetVulnerabilityTrends)
	return r
}

func doRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var reqBody *strings.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	} else {
		reqBody = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ── HealthCheck ───────────────────────────────────────────────────────────────

func TestHealthCheck(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/health", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ── CreateScan ────────────────────────────────────────────────────────────────

func TestCreateScan_Success(t *testing.T) {
	r := newRouter(&mockStore{})
	body := `{"ArtifactName":"nginx:1.25","ArtifactType":"container_image","Metadata":{},"Results":[]}`
	w := doRequest(r, http.MethodPost, "/scans", body)

	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp models.Scan
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.ImageName != "nginx" {
		t.Errorf("image_name: want nginx, got %s", resp.ImageName)
	}
	if resp.ImageTag != "1.25" {
		t.Errorf("image_tag: want 1.25, got %s", resp.ImageTag)
	}
}

func TestCreateScan_QueryParamOverride(t *testing.T) {
	// ArtifactName is absent - image/tag must come from query params.
	r := newRouter(&mockStore{})
	body := `{"ArtifactType":"container_image","Results":[]}`
	w := doRequest(r, http.MethodPost, "/scans?image=alpine&tag=3.19", body)

	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp models.Scan
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ImageName != "alpine" {
		t.Errorf("image_name: want alpine, got %s", resp.ImageName)
	}
	if resp.ImageTag != "3.19" {
		t.Errorf("image_tag: want 3.19, got %s", resp.ImageTag)
	}
}

func TestCreateScan_MissingImageName_Returns400(t *testing.T) {
	r := newRouter(&mockStore{})
	// No ArtifactName and no query params -> should 400.
	w := doRequest(r, http.MethodPost, "/scans", `{"ArtifactType":"container_image","Results":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestCreateScan_InvalidJSON_Returns400(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodPost, "/scans", `not-json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestCreateScan_StoreError_Returns500(t *testing.T) {
	store := &mockStore{
		createFn: func(_ context.Context, _, _, _ string, _ json.RawMessage, _ models.VulnCounts, _ []models.Vulnerability) (*models.Scan, bool, error) {
			return nil, false, &testError{"db failure"}
		},
	}
	r := newRouter(store)
	body := `{"ArtifactName":"nginx:1.25","Results":[]}`
	w := doRequest(r, http.MethodPost, "/scans", body)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", w.Code)
	}
}

// ── ListScans ─────────────────────────────────────────────────────────────────

func TestListScans_MissingTagOrImage_Returns400(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/scans", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestListScans_Success(t *testing.T) {
	store := &mockStore{
		listByTagFn: func(_ context.Context, tag string) ([]models.Scan, error) {
			return []models.Scan{{ID: "1", ImageName: "nginx", ImageTag: tag}}, nil
		},
	}
	w := doRequest(newRouter(store), http.MethodGet, "/scans?tag=1.25", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count int           `json:"count"`
		Items []models.Scan `json:"items"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestListScans_ByImageAndSeverity_Success(t *testing.T) {
	store := &mockStore{
		listByImageSeverityFn: func(_ context.Context, image, severity string) ([]models.Scan, error) {
			return []models.Scan{{ID: "2", ImageName: image, ImageTag: "latest"}}, nil
		},
	}
	w := doRequest(newRouter(store), http.MethodGet, "/scans?image=nginx&severity=CRITICAL", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Image    string        `json:"image"`
		Severity string        `json:"severity"`
		Count    int           `json:"count"`
		Items    []models.Scan `json:"items"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Image != "nginx" {
		t.Errorf("image: want nginx, got %q", resp.Image)
	}
	if resp.Severity != "CRITICAL" {
		t.Errorf("severity: want CRITICAL, got %q", resp.Severity)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestListScans_ByImageOnly_Success(t *testing.T) {
	store := &mockStore{
		listByImageFn: func(_ context.Context, image string) ([]models.Scan, error) {
			return []models.Scan{{ID: "3", ImageName: image, ImageTag: "1.25"}}, nil
		},
	}
	w := doRequest(newRouter(store), http.MethodGet, "/scans?image=nginx", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestListScans_Pagination_FallbackStore(t *testing.T) {
	store := &mockStore{
		listByTagFn: func(_ context.Context, tag string) ([]models.Scan, error) {
			return []models.Scan{
				{ID: "1", ImageName: "nginx", ImageTag: tag},
				{ID: "2", ImageName: "nginx", ImageTag: tag},
				{ID: "3", ImageName: "nginx", ImageTag: tag},
			}, nil
		},
	}

	w := doRequest(newRouter(store), http.MethodGet, "/scans?tag=1.25&limit=2&offset=1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count  int           `json:"count"`
		Limit  int           `json:"limit"`
		Offset int           `json:"offset"`
		Items  []models.Scan `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Count != 2 {
		t.Errorf("count: want 2, got %d", resp.Count)
	}
	if resp.Limit != 2 {
		t.Errorf("limit: want 2, got %d", resp.Limit)
	}
	if resp.Offset != 1 {
		t.Errorf("offset: want 1, got %d", resp.Offset)
	}
	if len(resp.Items) != 2 || resp.Items[0].ID != "2" || resp.Items[1].ID != "3" {
		t.Errorf("unexpected paginated ids: %+v", resp.Items)
	}
}

func TestListScans_Pagination_InvalidLimit(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/scans?tag=1.25&limit=-1", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestListAllScans_DefaultPagination(t *testing.T) {
	store := &mockStore{
		listAllPageFn: func(_ context.Context, _, _ string, limit, offset int) ([]models.Scan, error) {
			if limit != 100 {
				t.Fatalf("limit: want 100, got %d", limit)
			}
			if offset != 0 {
				t.Fatalf("offset: want 0, got %d", offset)
			}
			return []models.Scan{{ID: "a1"}}, nil
		},
	}

	w := doRequest(newRouter(store), http.MethodGet, "/scans/all", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestGetVulnerabilitySummary_Success(t *testing.T) {
	store := &mockStore{
		vulnerabilitySummary: func(_ context.Context, image string, from, to *time.Time) (*models.VulnerabilitySummary, error) {
			if image != "nginx" {
				t.Fatalf("image: want nginx, got %q", image)
			}
			if from == nil || to == nil {
				t.Fatal("expected from/to to be parsed")
			}
			return &models.VulnerabilitySummary{
				Image:                image,
				From:                 from,
				To:                   to,
				TotalScans:           2,
				TotalVulnerabilities: 3,
				SeverityCounts: []models.SeverityCount{
					{Severity: "CRITICAL", Count: 2},
					{Severity: "HIGH", Count: 1},
				},
			}, nil
		},
	}

	path := "/analytics/vulnerabilities/summary?image=nginx&from=2026-04-01T00:00:00Z&to=2026-04-30T23:59:59Z"
	w := doRequest(newRouter(store), http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		TotalScans           int64 `json:"total_scans"`
		TotalVulnerabilities int64 `json:"total_vulnerabilities"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TotalScans != 2 {
		t.Errorf("total_scans: want 2, got %d", resp.TotalScans)
	}
	if resp.TotalVulnerabilities != 3 {
		t.Errorf("total_vulnerabilities: want 3, got %d", resp.TotalVulnerabilities)
	}
}

func TestGetVulnerabilitySummary_InvalidFrom_Returns400(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/analytics/vulnerabilities/summary?from=not-a-time", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestGetVulnerabilityTrends_Success(t *testing.T) {
	store := &mockStore{
		vulnerabilityTrends: func(_ context.Context, image, interval string, _, _ *time.Time) ([]models.VulnerabilityTrendPoint, error) {
			if image != "nginx" {
				t.Fatalf("image: want nginx, got %q", image)
			}
			if interval != "day" {
				t.Fatalf("interval: want day, got %q", interval)
			}
			return []models.VulnerabilityTrendPoint{
				{Bucket: time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC), Severity: "CRITICAL", Count: 2},
			}, nil
		},
	}

	w := doRequest(newRouter(store), http.MethodGet, "/analytics/vulnerabilities/trends?image=nginx&interval=day", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestGetVulnerabilityTrends_InvalidInterval_Returns400(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/analytics/vulnerabilities/trends?interval=month", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ── GetLatestScan ─────────────────────────────────────────────────────────────

func TestGetLatestScan_MissingImage_Returns400(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/scans/latest", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestGetLatestScan_NotFound_Returns404(t *testing.T) {
	// mockStore.LatestByImage returns nil,nil by default → 404
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/scans/latest?image=ghost", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestGetLatestScan_Success(t *testing.T) {
	store := &mockStore{
		latestByImgFn: func(_ context.Context, image string) (*models.Scan, error) {
			return &models.Scan{ID: "99", ImageName: image, ImageTag: "latest"}, nil
		},
	}
	w := doRequest(newRouter(store), http.MethodGet, "/scans/latest?image=nginx", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestGetScanVulnerabilities_Success(t *testing.T) {
	scanRaw := json.RawMessage(`{
		"Results": [
			{
				"Target":"alpine:3.21",
				"Class":"os-pkgs",
				"Type":"alpine",
				"Vulnerabilities":[
					{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"openssl"},
					{"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"busybox"}
				]
			}
		]
	}`)
	store := &mockStore{
		getByIDFn: func(_ context.Context, id string) (*models.Scan, error) {
			return &models.Scan{ID: id, ImageName: "nginx", ImageTag: "1.25", ScanResult: scanRaw}, nil
		},
	}

	w := doRequest(newRouter(store), http.MethodGet, "/scans/scan-123/vulnerabilities?severity=HIGH&pkg=openssl", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestGetScanVulnerabilities_NotFound(t *testing.T) {
	w := doRequest(newRouter(&mockStore{}), http.MethodGet, "/scans/missing/vulnerabilities", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
