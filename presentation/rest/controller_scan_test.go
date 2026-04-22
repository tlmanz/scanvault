package rest_test

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
	"github.com/tlmanz/scanvault/domain/entities"
	"github.com/tlmanz/scanvault/domain/usecases"
	"github.com/tlmanz/scanvault/presentation/rest"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ── Stub repository (implements all boundary interfaces) ──────────────────────

type stubRepo struct {
	createFn                  func(ctx context.Context, name, tag, digest string, result json.RawMessage, vuln entities.VulnCounts, vulns []entities.Vulnerability) (*entities.Scan, bool, error)
	listByTagFn               func(ctx context.Context, tag string) ([]entities.Scan, error)
	listByTagPageFn           func(ctx context.Context, tag string, limit, offset int) ([]entities.Scan, error)
	listByImageFn             func(ctx context.Context, image string) ([]entities.Scan, error)
	listByImagePageFn         func(ctx context.Context, image string, limit, offset int) ([]entities.Scan, error)
	listByImageSeverityFn     func(ctx context.Context, image, severity string) ([]entities.Scan, error)
	listByImageSeverityPageFn func(ctx context.Context, image, severity string, limit, offset int) ([]entities.Scan, error)
	listAllPageFn             func(ctx context.Context, image, tag string, limit, offset int) ([]entities.Scan, error)
	latestByImgFn             func(ctx context.Context, image string) (*entities.Scan, error)
	getByIDFn                 func(ctx context.Context, id string) (*entities.Scan, error)
	vulnerabilitySummaryFn    func(ctx context.Context, image string, from, to *time.Time) (*entities.VulnerabilitySummary, error)
	vulnerabilityTrendsFn     func(ctx context.Context, image, interval string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error)
}

// ScanPersister
func (s *stubRepo) Create(ctx context.Context, name, tag, digest string, result json.RawMessage, vuln entities.VulnCounts, vulns []entities.Vulnerability) (*entities.Scan, bool, error) {
	if s.createFn != nil {
		return s.createFn(ctx, name, tag, digest, result, vuln, vulns)
	}
	return &entities.Scan{ID: "test-id", ImageName: name, ImageTag: tag, ScanResult: result, CreatedAt: time.Now()}, true, nil
}

// ScanRetriever
func (s *stubRepo) ListByTag(ctx context.Context, tag string) ([]entities.Scan, error) {
	if s.listByTagFn != nil {
		return s.listByTagFn(ctx, tag)
	}
	return []entities.Scan{}, nil
}
func (s *stubRepo) ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]entities.Scan, error) {
	if s.listByTagPageFn != nil {
		return s.listByTagPageFn(ctx, tag, limit, offset)
	}
	return s.ListByTag(ctx, tag)
}
func (s *stubRepo) ListByImage(ctx context.Context, image string) ([]entities.Scan, error) {
	if s.listByImageFn != nil {
		return s.listByImageFn(ctx, image)
	}
	return []entities.Scan{}, nil
}
func (s *stubRepo) ListByImagePage(ctx context.Context, image string, limit, offset int) ([]entities.Scan, error) {
	if s.listByImagePageFn != nil {
		return s.listByImagePageFn(ctx, image, limit, offset)
	}
	return s.ListByImage(ctx, image)
}
func (s *stubRepo) ListByImageWithSeverity(ctx context.Context, image, severity string) ([]entities.Scan, error) {
	if s.listByImageSeverityFn != nil {
		return s.listByImageSeverityFn(ctx, image, severity)
	}
	return []entities.Scan{}, nil
}
func (s *stubRepo) ListByImageWithSeverityPage(ctx context.Context, image, severity string, limit, offset int) ([]entities.Scan, error) {
	if s.listByImageSeverityPageFn != nil {
		return s.listByImageSeverityPageFn(ctx, image, severity, limit, offset)
	}
	return s.ListByImageWithSeverity(ctx, image, severity)
}
func (s *stubRepo) ListAllPage(ctx context.Context, image, tag string, limit, offset int) ([]entities.Scan, error) {
	if s.listAllPageFn != nil {
		return s.listAllPageFn(ctx, image, tag, limit, offset)
	}
	return []entities.Scan{}, nil
}
func (s *stubRepo) LatestByImage(ctx context.Context, image string) (*entities.Scan, error) {
	if s.latestByImgFn != nil {
		return s.latestByImgFn(ctx, image)
	}
	return nil, nil
}
func (s *stubRepo) GetByID(ctx context.Context, id string) (*entities.Scan, error) {
	if s.getByIDFn != nil {
		return s.getByIDFn(ctx, id)
	}
	return nil, nil
}

// ScanAnalytics
func (s *stubRepo) VulnerabilitySummary(ctx context.Context, image string, from, to *time.Time) (*entities.VulnerabilitySummary, error) {
	if s.vulnerabilitySummaryFn != nil {
		return s.vulnerabilitySummaryFn(ctx, image, from, to)
	}
	return &entities.VulnerabilitySummary{}, nil
}
func (s *stubRepo) VulnerabilityTrends(ctx context.Context, image, interval string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error) {
	if s.vulnerabilityTrendsFn != nil {
		return s.vulnerabilityTrendsFn(ctx, image, interval, from, to)
	}
	return []entities.VulnerabilityTrendPoint{}, nil
}
func (s *stubRepo) TopCVEs(ctx context.Context, image, severity string, limit int, from, to *time.Time) ([]entities.TopCVE, error) {
	return []entities.TopCVE{}, nil
}
func (s *stubRepo) CVEAffectedImages(ctx context.Context, cveID string) ([]entities.AffectedImage, error) {
	return []entities.AffectedImage{}, nil
}
func (s *stubRepo) FixableSummary(ctx context.Context, image string, from, to *time.Time) (*entities.FixableSummary, error) {
	return &entities.FixableSummary{}, nil
}

// ── Router helper ─────────────────────────────────────────────────────────────

func newRouter(repo *stubRepo) *gin.Engine {
	uc := usecases.NewScanUseCases(repo, repo, repo)
	h := rest.NewScanController(uc, zerolog.Nop())
	router := gin.New()
	rest.RegisterRoutes(router, h, true, "")
	return router
}

func doRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHealthCheck(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/health", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestCreateScan_EmptyBody_Returns400(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodPost, "/scans", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestCreateScan_MissingImageName_Returns400(t *testing.T) {
	body := `{"ArtifactName":"","Metadata":{},"Results":[]}`
	w := doRequest(newRouter(&stubRepo{}), http.MethodPost, "/scans", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestCreateScan_WithImageParam_Returns201(t *testing.T) {
	body := `{"ArtifactName":"","Metadata":{},"Results":[]}`
	w := doRequest(newRouter(&stubRepo{}), http.MethodPost, "/scans?image=nginx&tag=latest", body)
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestCreateScan_ValidPayload_Returns201(t *testing.T) {
	body := `{
		"ArtifactName": "nginx:1.25",
		"ArtifactType": "container_image",
		"Metadata": {"ImageID": "sha256:abc", "RepoTags": ["nginx:1.25"]},
		"Results": []
	}`
	w := doRequest(newRouter(&stubRepo{}), http.MethodPost, "/scans", body)
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestListScans_MissingTagAndImage_Returns400(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestListScans_ByTag_Returns200(t *testing.T) {
	repo := &stubRepo{
		listByTagFn: func(_ context.Context, tag string) ([]entities.Scan, error) {
			return []entities.Scan{{ID: "1", ImageName: "nginx", ImageTag: tag}}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/scans?tag=1.25", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestListScans_ByImage_Returns200(t *testing.T) {
	repo := &stubRepo{
		listByImageFn: func(_ context.Context, image string) ([]entities.Scan, error) {
			return []entities.Scan{{ID: "3", ImageName: image, ImageTag: "1.25"}}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/scans?image=nginx", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestListScans_Pagination_InvalidLimit(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans?tag=1.25&limit=-1", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestListAllScans_DefaultPagination(t *testing.T) {
	repo := &stubRepo{
		listAllPageFn: func(_ context.Context, _, _ string, limit, offset int) ([]entities.Scan, error) {
			if limit != 100 {
				t.Fatalf("limit: want 100, got %d", limit)
			}
			return []entities.Scan{{ID: "a1"}}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/scans/all", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestGetVulnerabilitySummary_Success(t *testing.T) {
	repo := &stubRepo{
		vulnerabilitySummaryFn: func(_ context.Context, image string, from, to *time.Time) (*entities.VulnerabilitySummary, error) {
			return &entities.VulnerabilitySummary{
				Image:                image,
				TotalScans:           2,
				TotalVulnerabilities: 3,
				SeverityCounts:       []entities.SeverityCount{{Severity: "CRITICAL", Count: 2}},
			}, nil
		},
	}
	path := "/analytics/vulnerabilities/summary?image=nginx&from=2026-04-01T00:00:00Z&to=2026-04-30T23:59:59Z"
	w := doRequest(newRouter(repo), http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		TotalScans int64 `json:"total_scans"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalScans != 2 {
		t.Errorf("total_scans: want 2, got %d", resp.TotalScans)
	}
}

func TestGetVulnerabilitySummary_InvalidFrom_Returns400(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/analytics/vulnerabilities/summary?from=not-a-time", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestGetVulnerabilityTrends_Success(t *testing.T) {
	repo := &stubRepo{
		vulnerabilityTrendsFn: func(_ context.Context, image, interval string, _, _ *time.Time) ([]entities.VulnerabilityTrendPoint, error) {
			return []entities.VulnerabilityTrendPoint{
				{Bucket: time.Now(), Severity: "CRITICAL", Count: 2},
			}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/analytics/vulnerabilities/trends?image=nginx&interval=day", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
}

func TestGetVulnerabilityTrends_InvalidInterval_Returns400(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/analytics/vulnerabilities/trends?interval=month", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestGetLatestScan_MissingImage_Returns400(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans/latest", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestGetLatestScan_NotFound_Returns404(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans/latest?image=ghost", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestGetLatestScan_Success(t *testing.T) {
	repo := &stubRepo{
		latestByImgFn: func(_ context.Context, image string) (*entities.Scan, error) {
			return &entities.Scan{ID: "99", ImageName: image, ImageTag: "latest"}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/scans/latest?image=nginx", "")
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestGetScanVulnerabilities_Success(t *testing.T) {
	scanRaw := json.RawMessage(`{"Results":[{"Target":"alpine","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"openssl"},{"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"busybox"}]}]}`)
	repo := &stubRepo{
		getByIDFn: func(_ context.Context, id string) (*entities.Scan, error) {
			return &entities.Scan{ID: id, ImageName: "nginx", ImageTag: "1.25", ScanResult: scanRaw}, nil
		},
	}
	w := doRequest(newRouter(repo), http.MethodGet, "/scans/scan-123/vulnerabilities?severity=HIGH&pkg=openssl", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestGetScanVulnerabilities_NotFound(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans/missing/vulnerabilities", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}
