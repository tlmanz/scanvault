// Package usecases contains all business logic for ScanVault.
// Use cases orchestrate boundary interfaces and enforce domain rules —
// they must not import anything from the presentation or persistence layers.
package usecases

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tlmanz/scanvault/domain/boundary"
	"github.com/tlmanz/scanvault/domain/entities"
)

// ScanUseCases orchestrates all scan-related business operations.
type ScanUseCases struct {
	persister boundary.ScanPersister
	retriever boundary.ScanRetriever
	analytics boundary.ScanAnalytics
}

// NewScanUseCases creates a new ScanUseCases, injecting its dependencies
// through the boundary interfaces (dependency inversion).
func NewScanUseCases(
	persister boundary.ScanPersister,
	retriever boundary.ScanRetriever,
	analytics boundary.ScanAnalytics,
) *ScanUseCases {
	return &ScanUseCases{
		persister: persister,
		retriever: retriever,
		analytics: analytics,
	}
}

// ─── Write operations ─────────────────────────────────────────────────────────

// CreateScan stores a new scan record and its vulnerability rows.
func (s *ScanUseCases) CreateScan(
	ctx context.Context,
	imageName, imageTag, imageDigest string,
	scanResult json.RawMessage,
	vuln entities.VulnCounts,
	vulns []entities.Vulnerability,
) (*entities.Scan, bool, error) {
	return s.persister.Create(ctx, imageName, imageTag, imageDigest, scanResult, vuln, vulns)
}

// ─── Retrieval operations ─────────────────────────────────────────────────────

// GetScanByID returns a scan by its UUID.
func (s *ScanUseCases) GetScanByID(ctx context.Context, id string) (*entities.Scan, error) {
	return s.retriever.GetByID(ctx, id)
}

// GetLatestScan returns the most recent scan for the given image name.
func (s *ScanUseCases) GetLatestScan(ctx context.Context, imageName string) (*entities.Scan, error) {
	return s.retriever.LatestByImage(ctx, imageName)
}

// ListByTag returns scans for a tag, with optional pagination.
func (s *ScanUseCases) ListByTag(ctx context.Context, tag string, limit, offset int, paginate bool) ([]entities.Scan, error) {
	if !paginate {
		return s.retriever.ListByTag(ctx, tag)
	}
	return s.retriever.ListByTagPage(ctx, tag, limit, offset)
}

// ListByImage returns scans for an image, with optional pagination.
func (s *ScanUseCases) ListByImage(ctx context.Context, imageName string, limit, offset int, paginate bool) ([]entities.Scan, error) {
	if !paginate {
		return s.retriever.ListByImage(ctx, imageName)
	}
	return s.retriever.ListByImagePage(ctx, imageName, limit, offset)
}

// ListByImageWithSeverity returns scans for an image filtered by severity, with optional pagination.
func (s *ScanUseCases) ListByImageWithSeverity(ctx context.Context, imageName, severity string, limit, offset int, paginate bool) ([]entities.Scan, error) {
	if !paginate {
		return s.retriever.ListByImageWithSeverity(ctx, imageName, severity)
	}
	return s.retriever.ListByImageWithSeverityPage(ctx, imageName, severity, limit, offset)
}

// ListAllPage returns all scans with optional image/tag filters and pagination.
func (s *ScanUseCases) ListAllPage(ctx context.Context, imageName, tag string, limit, offset int) ([]entities.Scan, error) {
	return s.retriever.ListAllPage(ctx, imageName, tag, limit, offset)
}

// ─── Analytics operations ─────────────────────────────────────────────────────

// GetVulnerabilitySummary returns aggregate vulnerability counts.
func (s *ScanUseCases) GetVulnerabilitySummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.VulnerabilitySummary, error) {
	return s.analytics.VulnerabilitySummary(ctx, imageName, from, to)
}

// GetVulnerabilityTrends returns vulnerability counts bucketed by day or week.
func (s *ScanUseCases) GetVulnerabilityTrends(ctx context.Context, imageName, bucket string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error) {
	return s.analytics.VulnerabilityTrends(ctx, imageName, bucket, from, to)
}

// GetTopCVEs returns the most common CVEs across all images.
func (s *ScanUseCases) GetTopCVEs(ctx context.Context, imageName, severity string, limit int, from, to *time.Time) ([]entities.TopCVE, error) {
	return s.analytics.TopCVEs(ctx, imageName, severity, limit, from, to)
}

// GetCVEAffectedImages returns all images currently exposed to a specific CVE.
func (s *ScanUseCases) GetCVEAffectedImages(ctx context.Context, cveID string) ([]entities.AffectedImage, error) {
	return s.analytics.CVEAffectedImages(ctx, cveID)
}

// GetFixableSummary returns how many current vulnerabilities have a known fix.
func (s *ScanUseCases) GetFixableSummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.FixableSummary, error) {
	return s.analytics.FixableSummary(ctx, imageName, from, to)
}
