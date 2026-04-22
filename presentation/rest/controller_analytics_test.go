package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tlmanz/scanvault/domain/entities"
)

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
		TotalScans int64 `json:"TotalScans"`
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

func TestGetTopCVEs_Success(t *testing.T) {
	repo := &stubRepo{
		topCVEsFn: func(_ context.Context, image, severity string, limit int, _, _ *time.Time) ([]entities.TopCVE, error) {
			if limit != 5 {
				t.Errorf("limit: want 5, got %d", limit)
			}
			return []entities.TopCVE{
				{CVEID: "CVE-2026-0001", Severity: "CRITICAL", ImageCount: 10, Fixable: true},
				{CVEID: "CVE-2026-0002", Severity: "HIGH", ImageCount: 5, Fixable: false},
			}, nil
		},
	}
	path := "/analytics/vulnerabilities/top-cves?limit=5"
	w := doRequest(newRouter(repo), http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count int `json:"Count"`
		Limit int `json:"Limit"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("count: want 2, got %d", resp.Count)
	}
	if resp.Limit != 5 {
		t.Errorf("limit: want 5, got %d", resp.Limit)
	}
}

func TestGetCVEAffectedImages_Success(t *testing.T) {
	repo := &stubRepo{
		cveAffectedImagesFn: func(_ context.Context, cveID string) ([]entities.AffectedImage, error) {
			if cveID != "CVE-2026-0001" {
				t.Errorf("cve_id: want CVE-2026-0001, got %s", cveID)
			}
			return []entities.AffectedImage{
				{ImageName: "nginx", ImageTag: "1.25", PkgName: "openssl"},
			}, nil
		},
	}
	path := "/analytics/vulnerabilities/cve/CVE-2026-0001/images"
	w := doRequest(newRouter(repo), http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		CVEID string `json:"CVEID"`
		Count int    `json:"Count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CVEID != "CVE-2026-0001" {
		t.Errorf("cve_id: want CVE-2026-0001, got %s", resp.CVEID)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
}

func TestGetFixableSummary_Success(t *testing.T) {
	repo := &stubRepo{
		fixableSummaryFn: func(_ context.Context, image string, _, _ *time.Time) (*entities.FixableSummary, error) {
			return &entities.FixableSummary{
				TotalVulns: 10,
				Fixable:    4,
				NotFixable: 6,
				FixablePct: 40.0,
			}, nil
		},
	}
	path := "/analytics/vulnerabilities/fixable?image=nginx"
	w := doRequest(newRouter(repo), http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d - body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		TotalVulns int64   `json:"TotalVulns"`
		Fixable    int64   `json:"Fixable"`
		FixablePct float64 `json:"FixablePct"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalVulns != 10 {
		t.Errorf("total_vulns: want 10, got %d", resp.TotalVulns)
	}
	if resp.Fixable != 4 {
		t.Errorf("fixable: want 4, got %d", resp.Fixable)
	}
	if resp.FixablePct != 40.0 {
		t.Errorf("fixable_pct: want 40.0, got %f", resp.FixablePct)
	}
}
