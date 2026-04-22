package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tlmanz/scanvault/domain/entities"
)

func init() {
	gin.SetMode(gin.TestMode)
}

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
	scanRaw := json.RawMessage(`{"Results":[{"Target":"alpine","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"openssl","InstalledVersion":"1.1.1"},{"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"busybox","InstalledVersion":"1.35.0"}]}]}`)
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
		Count int `json:"Count"`
		Items []struct {
			Vulnerability struct {
				PkgVersion string `json:"PkgVersion"`
			} `json:"Vulnerability"`
		} `json:"Items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count: want 1, got %d", resp.Count)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items: want 1, got %d", len(resp.Items))
	}
	if resp.Items[0].Vulnerability.PkgVersion != "1.1.1" {
		t.Fatalf("pkg_version: want 1.1.1, got %q", resp.Items[0].Vulnerability.PkgVersion)
	}
}

func TestGetScanVulnerabilities_NotFound(t *testing.T) {
	w := doRequest(newRouter(&stubRepo{}), http.MethodGet, "/scans/missing/vulnerabilities", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}
