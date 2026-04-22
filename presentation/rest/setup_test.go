package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

	vulnerabilitySummaryFn func(ctx context.Context, image string, from, to *time.Time) (*entities.VulnerabilitySummary, error)
	vulnerabilityTrendsFn  func(ctx context.Context, image, interval string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error)
	topCVEsFn              func(ctx context.Context, image, severity string, limit int, from, to *time.Time) ([]entities.TopCVE, error)
	cveAffectedImagesFn    func(ctx context.Context, cveID string) ([]entities.AffectedImage, error)
	fixableSummaryFn       func(ctx context.Context, image string, from, to *time.Time) (*entities.FixableSummary, error)
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
	if s.topCVEsFn != nil {
		return s.topCVEsFn(ctx, image, severity, limit, from, to)
	}
	return []entities.TopCVE{}, nil
}
func (s *stubRepo) CVEAffectedImages(ctx context.Context, cveID string) ([]entities.AffectedImage, error) {
	if s.cveAffectedImagesFn != nil {
		return s.cveAffectedImagesFn(ctx, cveID)
	}
	return []entities.AffectedImage{}, nil
}
func (s *stubRepo) FixableSummary(ctx context.Context, image string, from, to *time.Time) (*entities.FixableSummary, error) {
	if s.fixableSummaryFn != nil {
		return s.fixableSummaryFn(ctx, image, from, to)
	}
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
