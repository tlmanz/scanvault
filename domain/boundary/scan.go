// Package boundary defines the contracts (Go interfaces) between the domain
// and the outer orchestration layers. Any persistence or external resource
// needed by the domain must be expressed as a boundary interface here.
//
// The Persistence layer (persistence/postgres) implements these interfaces.
// The Domain layer (domain/usecases) depends only on these interfaces, never
// on concrete implementations — this is dependency inversion.
package boundary

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tlmanz/scanvault/domain/entities"
)

// ScanPersister handles write operations for scan records.
type ScanPersister interface {
	// Create inserts or updates a scan record and its associated vulnerability
	// rows atomically within a transaction. Returns the persisted scan and a
	// boolean indicating whether a new row was created (true) or an existing
	// digest row was updated (false).
	Create(
		ctx context.Context,
		imageName, imageTag, imageDigest string,
		scanResult json.RawMessage,
		vuln entities.VulnCounts,
		vulns []entities.Vulnerability,
	) (*entities.Scan, bool, error)
}

// ScanRetriever handles read operations for scan records.
type ScanRetriever interface {
	// GetByID returns a scan by its UUID. Returns nil, nil when not found.
	GetByID(ctx context.Context, id string) (*entities.Scan, error)

	// LatestByImage returns the most recent scan for a given image name.
	// Returns nil, nil when no scan exists.
	LatestByImage(ctx context.Context, imageName string) (*entities.Scan, error)

	// ListByTag returns all scans for a given image tag, newest first.
	ListByTag(ctx context.Context, tag string) ([]entities.Scan, error)

	// ListByTagPage is the paginated variant of ListByTag (limit=-1 = no limit).
	ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]entities.Scan, error)

	// ListByImage returns all scans for a given image name, newest first.
	ListByImage(ctx context.Context, imageName string) ([]entities.Scan, error)

	// ListByImagePage is the paginated variant of ListByImage.
	ListByImagePage(ctx context.Context, imageName string, limit, offset int) ([]entities.Scan, error)

	// ListByImageWithSeverity returns scans for an image that have at least one
	// vulnerability of the given severity.
	ListByImageWithSeverity(ctx context.Context, imageName, severity string) ([]entities.Scan, error)

	// ListByImageWithSeverityPage is the paginated variant of ListByImageWithSeverity.
	ListByImageWithSeverityPage(ctx context.Context, imageName, severity string, limit, offset int) ([]entities.Scan, error)

	// ListAllPage returns scans with optional image/tag filters and pagination.
	ListAllPage(ctx context.Context, imageName, tag string, limit, offset int) ([]entities.Scan, error)
}

// ScanAnalytics handles analytics / aggregate queries over scan data.
type ScanAnalytics interface {
	// VulnerabilitySummary returns aggregate vulnerability counts, optionally
	// filtered by image and time range.
	VulnerabilitySummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.VulnerabilitySummary, error)

	// VulnerabilityTrends returns vulnerability counts bucketed by day or week.
	VulnerabilityTrends(ctx context.Context, imageName, bucket string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error)

	// TopCVEs returns the most common CVEs across the latest scan of each image:tag.
	TopCVEs(ctx context.Context, imageName, severity string, limit int, from, to *time.Time) ([]entities.TopCVE, error)

	// CVEAffectedImages returns all images currently exposed to a specific CVE.
	CVEAffectedImages(ctx context.Context, cveID string) ([]entities.AffectedImage, error)

	// FixableSummary returns how many current vulnerabilities have a known fix.
	FixableSummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.FixableSummary, error)
}

// ScanCleaner handles deletion / retention operations for scan records.
type ScanCleaner interface {
	// DeleteOlderThan removes all scans whose created_at is older than age.
	DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error)

	// DeleteExcessPerImage keeps only the <keep> most recent scans per image name.
	DeleteExcessPerImage(ctx context.Context, keep int) (int64, error)

	// DeleteExcessAndOld deletes scans that fail BOTH retention policies: older
	// than age AND ranked outside the top <keep> for their image.
	DeleteExcessAndOld(ctx context.Context, age time.Duration, keep int) (int64, error)
}
