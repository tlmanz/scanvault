package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tlmanz/scanvault/models"
)



// ScanRepository handles all database operations for scan records.
type ScanRepository struct {
	pool *pgxpool.Pool
}

// New creates a new ScanRepository.
func New(pool *pgxpool.Pool) *ScanRepository {
	return &ScanRepository{pool: pool}
}

// Create inserts or updates a scan record and its associated vulnerability rows
// atomically within a transaction. Returns the persisted scan and a boolean
// indicating whether a new row was created (true) or an existing digest row
// was updated (false).
//
// Deduplication rules:
//   - image_digest non-empty → upsert: same digest = same immutable image.
//   - image_digest empty     → always insert: mutable tags may change over time.
func (r *ScanRepository) Create(ctx context.Context, imageName, imageTag, imageDigest string, scanResult json.RawMessage, vuln models.VulnCounts, vulns []models.Vulnerability) (*models.Scan, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// ── 1. Upsert the scan row ──────────────────────────────────────────────
	const upsertQuery = `
		INSERT INTO scans (image_name, image_tag, image_digest, scan_result,
		                   vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (image_name, image_digest) WHERE image_digest != ''
		DO UPDATE SET
		  image_tag     = EXCLUDED.image_tag,
		  scan_result   = EXCLUDED.scan_result,
		  vuln_critical = EXCLUDED.vuln_critical,
		  vuln_high     = EXCLUDED.vuln_high,
		  vuln_medium   = EXCLUDED.vuln_medium,
		  vuln_low      = EXCLUDED.vuln_low,
		  vuln_unknown  = EXCLUDED.vuln_unknown,
		  created_at    = NOW()
		RETURNING id, image_name, image_tag, image_digest, scan_result, created_at,
		          vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown,
		          (xmax = 0) AS was_inserted`

	var scan models.Scan
	var rawJSON []byte
	var wasInserted bool

	row := tx.QueryRow(ctx, upsertQuery,
		imageName, imageTag, imageDigest, []byte(scanResult),
		vuln.Critical, vuln.High, vuln.Medium, vuln.Low, vuln.Unknown)
	if err := row.Scan(
		&scan.ID, &scan.ImageName, &scan.ImageTag, &scan.ImageDigest,
		&rawJSON, &scan.CreatedAt,
		&scan.VulnCritical, &scan.VulnHigh, &scan.VulnMedium, &scan.VulnLow, &scan.VulnUnknown,
		&wasInserted,
	); err != nil {
		return nil, false, fmt.Errorf("upserting scan: %w", err)
	}
	scan.ScanResult = json.RawMessage(rawJSON)

	// ── 2. Replace vulnerability rows for this scan ─────────────────────────
	// On upsert the scan_id stays the same, so we must clear stale entries first.
	if _, err := tx.Exec(ctx, `DELETE FROM vulnerabilities WHERE scan_id = $1`, scan.ID); err != nil {
		return nil, false, fmt.Errorf("clearing old vulnerabilities: %w", err)
	}

	if len(vulns) > 0 {
		// pgx.CopyFrom streams rows over the PostgreSQL COPY protocol — much faster
		// than individual INSERTs for large vulnerability lists.
		rows := make([][]any, len(vulns))
		for i, v := range vulns {
			rows[i] = []any{scan.ID, v.CVEID, v.PkgName, v.PkgVersion, v.FixedVersion, v.Severity, v.Title}
		}
		_, err = tx.CopyFrom(
			ctx,
			pgx.Identifier{"vulnerabilities"},
			[]string{"scan_id", "cve_id", "pkg_name", "pkg_version", "fixed_version", "severity", "title"},
			pgx.CopyFromRows(rows),
		)
		if err != nil {
			return nil, false, fmt.Errorf("bulk inserting vulnerabilities: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("committing scan transaction: %w", err)
	}

	return &scan, wasInserted, nil
}



// ListByTag returns all scans for a given image tag, newest first.
func (r *ScanRepository) ListByTag(ctx context.Context, tag string) ([]models.Scan, error) {
	return r.ListByTagPage(ctx, tag, -1, 0)
}

// ListByTagPage returns scans for a tag with optional pagination (limit=-1 = no limit).
func (r *ScanRepository) ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]models.Scan, error) {
	const base = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans WHERE image_tag = $1 ORDER BY created_at DESC`

	if limit < 0 {
		rows, err := r.pool.Query(ctx, base+" OFFSET $2", tag, offset)
		if err != nil {
			return nil, fmt.Errorf("querying scans by tag: %w", err)
		}
		defer rows.Close()
		return scanRows(rows)
	}
	rows, err := r.pool.Query(ctx, base+" LIMIT $2 OFFSET $3", tag, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying scans by tag: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// ListByImage returns all scans for a given image name, newest first.
func (r *ScanRepository) ListByImage(ctx context.Context, imageName string) ([]models.Scan, error) {
	return r.ListByImagePage(ctx, imageName, -1, 0)
}

// ListByImagePage returns scans for an image with optional pagination.
func (r *ScanRepository) ListByImagePage(ctx context.Context, imageName string, limit, offset int) ([]models.Scan, error) {
	const base = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans WHERE image_name = $1 ORDER BY created_at DESC`

	if limit < 0 {
		rows, err := r.pool.Query(ctx, base+" OFFSET $2", imageName, offset)
		if err != nil {
			return nil, fmt.Errorf("querying scans by image: %w", err)
		}
		defer rows.Close()
		return scanRows(rows)
	}
	rows, err := r.pool.Query(ctx, base+" LIMIT $2 OFFSET $3", imageName, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying scans by image: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// ListAllPage returns scans with optional image/tag filters and pagination.
func (r *ScanRepository) ListAllPage(ctx context.Context, imageName, tag string, limit, offset int) ([]models.Scan, error) {
	var q strings.Builder
	q.WriteString(`
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans WHERE 1=1`)

	args := []any{}
	if imageName != "" {
		args = append(args, imageName)
		q.WriteString(fmt.Sprintf("\n\t\tAND image_name = $%d", len(args)))
	}
	if tag != "" {
		args = append(args, tag)
		q.WriteString(fmt.Sprintf("\n\t\tAND image_tag = $%d", len(args)))
	}

	q.WriteString("\n\t\tORDER BY created_at DESC")

	if limit < 0 {
		args = append(args, offset)
		q.WriteString(fmt.Sprintf("\n\t\tOFFSET $%d", len(args)))
	} else {
		args = append(args, limit)
		q.WriteString(fmt.Sprintf("\n\t\tLIMIT $%d", len(args)))
		args = append(args, offset)
		q.WriteString(fmt.Sprintf(" OFFSET $%d", len(args)))
	}

	rows, err := r.pool.Query(ctx, q.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("querying all scans: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// ListByImageWithSeverity returns scans for an image that have at least one
// vulnerability of the given severity, using the pre-computed indexed columns
// — no JSONB scan on the hot path.
func (r *ScanRepository) ListByImageWithSeverity(ctx context.Context, imageName, severity string) ([]models.Scan, error) {
	return r.ListByImageWithSeverityPage(ctx, imageName, severity, -1, 0)
}

// ListByImageWithSeverityPage is the paginated variant of ListByImageWithSeverity.
func (r *ScanRepository) ListByImageWithSeverityPage(ctx context.Context, imageName, severity string, limit, offset int) ([]models.Scan, error) {
	col, err := severityColumn(severity)
	if err != nil {
		return nil, err
	}

	// col comes from our allow-list in severityColumn — safe to interpolate.
	base := fmt.Sprintf(`
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans
		WHERE image_name = $1 AND %s > 0
		ORDER BY created_at DESC`, col)

	if limit < 0 {
		rows, err := r.pool.Query(ctx, base+" OFFSET $2", imageName, offset)
		if err != nil {
			return nil, fmt.Errorf("querying scans by image and severity: %w", err)
		}
		defer rows.Close()
		return scanRows(rows)
	}
	rows, err := r.pool.Query(ctx, base+" LIMIT $2 OFFSET $3", imageName, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying scans by image and severity: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// severityColumn maps a severity string to the pre-computed column name.
// Returns an error for unrecognised values to prevent SQL injection.
func severityColumn(severity string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "vuln_critical", nil
	case "HIGH":
		return "vuln_high", nil
	case "MEDIUM":
		return "vuln_medium", nil
	case "LOW":
		return "vuln_low", nil
	case "UNKNOWN":
		return "vuln_unknown", nil
	default:
		return "", fmt.Errorf("unrecognised severity %q: must be CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN", severity)
	}
}

// VulnerabilitySummary returns aggregate vulnerability counts, optionally filtered by image and time range.
// Deduplicates by taking only the LATEST scan per (image_name, image_tag) before aggregating,
// so rescanning the same tag never inflates the totals.
func (r *ScanRepository) VulnerabilitySummary(ctx context.Context, imageName string, from, to *time.Time) (*models.VulnerabilitySummary, error) {
	var (
		fromArg any
		toArg   any
	)
	if from != nil {
		fromArg = *from
	}
	if to != nil {
		toArg = *to
	}

	summary := &models.VulnerabilitySummary{
		Image:          imageName,
		From:           from,
		To:             to,
		SeverityCounts: []models.SeverityCount{},
	}

	// DISTINCT ON picks the latest scan per (image_name, image_tag), so
	// rescanning the same image:tag never inflates counts.
	const query = `
		WITH latest_per_tag AS (
			SELECT DISTINCT ON (image_name, image_tag)
				vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
			FROM scans
			WHERE ($1 = '' OR image_name = $1)
			  AND ($2::timestamptz IS NULL OR created_at >= $2::timestamptz)
			  AND ($3::timestamptz IS NULL OR created_at <= $3::timestamptz)
			ORDER BY image_name, image_tag, created_at DESC
		)
		SELECT
			COUNT(*)                                                          AS total_tags,
			COALESCE(SUM(vuln_critical + vuln_high + vuln_medium
			             + vuln_low + vuln_unknown), 0)                       AS total_vulns,
			COALESCE(SUM(vuln_critical), 0)                                   AS critical,
			COALESCE(SUM(vuln_high),     0)                                   AS high,
			COALESCE(SUM(vuln_medium),   0)                                   AS medium,
			COALESCE(SUM(vuln_low),      0)                                   AS low,
			COALESCE(SUM(vuln_unknown),  0)                                   AS unknown
		FROM latest_per_tag`

	var critical, high, medium, low, unknown int64
	if err := r.pool.QueryRow(ctx, query, imageName, fromArg, toArg).Scan(
		&summary.TotalScans,
		&summary.TotalVulnerabilities,
		&critical, &high, &medium, &low, &unknown,
	); err != nil {
		return nil, fmt.Errorf("querying vulnerability summary: %w", err)
	}

	for _, sc := range []models.SeverityCount{
		{Severity: "CRITICAL", Count: critical},
		{Severity: "HIGH", Count: high},
		{Severity: "MEDIUM", Count: medium},
		{Severity: "LOW", Count: low},
		{Severity: "UNKNOWN", Count: unknown},
	} {
		if sc.Count > 0 {
			summary.SeverityCounts = append(summary.SeverityCounts, sc)
		}
	}

	// Populate top 10 CVEs inline — reuses TopCVEs with the same filters.
	topCVEs, err := r.TopCVEs(ctx, imageName, "", 10, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying top CVEs for summary: %w", err)
	}
	summary.TopCVEs = topCVEs

	return summary, nil
}


// VulnerabilityTrends returns vulnerability counts bucketed by day or week.
// Deduplicates within each bucket by taking only the latest scan per
// (image_name, image_tag, bucket) so rescans don't inflate trend counts.
func (r *ScanRepository) VulnerabilityTrends(ctx context.Context, imageName, bucket string, from, to *time.Time) ([]models.VulnerabilityTrendPoint, error) {
	if bucket != "day" && bucket != "week" {
		return nil, fmt.Errorf("invalid bucket %q", bucket)
	}

	var (
		fromArg any
		toArg   any
	)
	if from != nil {
		fromArg = *from
	}
	if to != nil {
		toArg = *to
	}

	// DISTINCT ON (image_name, image_tag, bucket) keeps only the latest scan
	// per tag per time bucket, then we aggregate across tags within the bucket.
	query := fmt.Sprintf(`
		WITH latest_per_tag_bucket AS (
			SELECT DISTINCT ON (image_name, image_tag, date_trunc('%s', created_at))
				date_trunc('%s', created_at) AS bucket,
				vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
			FROM scans
			WHERE ($1 = '' OR image_name = $1)
			  AND ($2::timestamptz IS NULL OR created_at >= $2::timestamptz)
			  AND ($3::timestamptz IS NULL OR created_at <= $3::timestamptz)
			ORDER BY image_name, image_tag, date_trunc('%s', created_at), created_at DESC
		)
		SELECT
			bucket,
			unnest(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']) AS severity,
			unnest(ARRAY[
				SUM(vuln_critical), SUM(vuln_high), SUM(vuln_medium),
				SUM(vuln_low),      SUM(vuln_unknown)
			]) AS count
		FROM latest_per_tag_bucket
		GROUP BY bucket
		ORDER BY bucket ASC, severity ASC`, bucket, bucket, bucket)

	rows, err := r.pool.Query(ctx, query, imageName, fromArg, toArg)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerability trends: %w", err)
	}
	defer rows.Close()

	points := []models.VulnerabilityTrendPoint{}
	for rows.Next() {
		var p models.VulnerabilityTrendPoint
		if err := rows.Scan(&p.Bucket, &p.Severity, &p.Count); err != nil {
			return nil, fmt.Errorf("scanning vulnerability trend row: %w", err)
		}
		if p.Count > 0 {
			points = append(points, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability trend rows: %w", err)
	}

	return points, nil
}


// LatestByImage returns the most recent scan for a given image name.
// Returns nil, nil when no scan exists.
func (r *ScanRepository) LatestByImage(ctx context.Context, imageName string) (*models.Scan, error) {
	const query = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans
		WHERE image_name = $1
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.pool.QueryRow(ctx, query, imageName)
	return scanSingleRowFromResult(row)
}

// GetByID returns a scan by its UUID.
// Returns nil, nil when no scan exists.
func (r *ScanRepository) GetByID(ctx context.Context, id string) (*models.Scan, error) {
	const query = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
		       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown
		FROM scans
		WHERE id = $1
		LIMIT 1`

	row := r.pool.QueryRow(ctx, query, id)
	return scanSingleRowFromResult(row)
}

// scanSingleRowFromResult scans one full row from a pgx.Row into a Scan.
func scanSingleRowFromResult(row pgx.Row) (*models.Scan, error) {
	var scan models.Scan
	var rawJSON []byte
	if err := row.Scan(
		&scan.ID,
		&scan.ImageName,
		&scan.ImageTag,
		&scan.ImageDigest,
		&rawJSON,
		&scan.CreatedAt,
		&scan.VulnCritical,
		&scan.VulnHigh,
		&scan.VulnMedium,
		&scan.VulnLow,
		&scan.VulnUnknown,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scanning scan row: %w", err)
	}
	scan.ScanResult = json.RawMessage(rawJSON)
	return &scan, nil
}

// scanRows collects multiple rows into a Scan slice.
func scanRows(rows pgx.Rows) ([]models.Scan, error) {
	var scans []models.Scan
	for rows.Next() {
		var scan models.Scan
		var rawJSON []byte
		if err := rows.Scan(
			&scan.ID,
			&scan.ImageName,
			&scan.ImageTag,
			&scan.ImageDigest,
			&rawJSON,
			&scan.CreatedAt,
			&scan.VulnCritical,
			&scan.VulnHigh,
			&scan.VulnMedium,
			&scan.VulnLow,
			&scan.VulnUnknown,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		scan.ScanResult = json.RawMessage(rawJSON)
		scans = append(scans, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}
	if scans == nil {
		scans = []models.Scan{}
	}
	return scans, nil
}

// DeleteOlderThan removes all scans whose created_at is older than the given duration.
func (r *ScanRepository) DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM scans WHERE created_at < NOW() - $1::interval`, age.String())
	if err != nil {
		return 0, fmt.Errorf("deleting old scans: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExcessPerImage keeps only the <keep> most recent scans per image name.
func (r *ScanRepository) DeleteExcessPerImage(ctx context.Context, keep int) (int64, error) {
	const query = `
		DELETE FROM scans
		WHERE id IN (
			SELECT id FROM (
				SELECT id,
					ROW_NUMBER() OVER (PARTITION BY image_name ORDER BY created_at DESC) AS rn
				FROM scans
			) ranked
			WHERE rn > $1
		)`
	tag, err := r.pool.Exec(ctx, query, keep)
	if err != nil {
		return 0, fmt.Errorf("deleting excess scans per image: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExcessAndOld deletes scans that fail BOTH retention policies: older than age
// AND ranked outside the top <keep> for their image.
func (r *ScanRepository) DeleteExcessAndOld(ctx context.Context, age time.Duration, keep int) (int64, error) {
	const query = `
		DELETE FROM scans
		WHERE id IN (
			SELECT id FROM (
				SELECT id,
					created_at,
					ROW_NUMBER() OVER (PARTITION BY image_name ORDER BY created_at DESC) AS rn
				FROM scans
			) ranked
			WHERE rn > $2
			AND   created_at < NOW() - $1::interval
		)`
	tag, err := r.pool.Exec(ctx, query, age.String(), keep)
	if err != nil {
		return 0, fmt.Errorf("deleting excess old scans: %w", err)
	}
	return tag.RowsAffected(), nil
}

// TopCVEs returns the most common CVEs across the latest scan of each image:tag,
// optionally filtered by image name, severity, and time range.
// Results are ordered by number of affected images descending.
func (r *ScanRepository) TopCVEs(ctx context.Context, imageName, severity string, limit int, from, to *time.Time) ([]models.TopCVE, error) {
	if limit <= 0 {
		limit = 10
	}

	var fromArg, toArg any
	if from != nil {
		fromArg = *from
	}
	if to != nil {
		toArg = *to
	}

	// Deduplicate to latest scan per (image_name, image_tag) then aggregate CVEs.
	const query = `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.image_name, s.image_tag) s.id, s.image_name
			FROM scans s
			WHERE ($1 = '' OR s.image_name = $1)
			  AND ($3::timestamptz IS NULL OR s.created_at >= $3::timestamptz)
			  AND ($4::timestamptz IS NULL OR s.created_at <= $4::timestamptz)
			ORDER BY s.image_name, s.image_tag, s.created_at DESC
		)
		SELECT
			v.cve_id,
			v.severity,
			MAX(v.title)                                  AS title,
			COUNT(DISTINCT ls.image_name)                 AS image_count,
			bool_or(v.fixed_version != '')                AS fixable
		FROM vulnerabilities v
		JOIN latest_scans ls ON ls.id = v.scan_id
		WHERE ($2 = '' OR v.severity = UPPER($2))
		GROUP BY v.cve_id, v.severity
		ORDER BY image_count DESC, v.cve_id ASC
		LIMIT $5`

	rows, err := r.pool.Query(ctx, query, imageName, severity, fromArg, toArg, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top CVEs: %w", err)
	}
	defer rows.Close()

	var out []models.TopCVE
	for rows.Next() {
		var c models.TopCVE
		if err := rows.Scan(&c.CVEID, &c.Severity, &c.Title, &c.ImageCount, &c.Fixable); err != nil {
			return nil, fmt.Errorf("scanning top CVE row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating top CVE rows: %w", err)
	}
	if out == nil {
		out = []models.TopCVE{}
	}
	return out, nil
}

// CVEAffectedImages returns all images currently exposed to a specific CVE,
// using the latest scan per (image_name, image_tag) for deduplication.
func (r *ScanRepository) CVEAffectedImages(ctx context.Context, cveID string) ([]models.AffectedImage, error) {
	const query = `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.image_name, s.image_tag)
				s.id, s.image_name, s.image_tag, s.created_at
			FROM scans s
			ORDER BY s.image_name, s.image_tag, s.created_at DESC
		)
		SELECT
			ls.image_name,
			ls.image_tag,
			v.pkg_name,
			v.pkg_version,
			v.fixed_version,
			ls.created_at
		FROM vulnerabilities v
		JOIN latest_scans ls ON ls.id = v.scan_id
		WHERE v.cve_id = $1
		ORDER BY ls.image_name, ls.image_tag`

	rows, err := r.pool.Query(ctx, query, cveID)
	if err != nil {
		return nil, fmt.Errorf("querying CVE affected images: %w", err)
	}
	defer rows.Close()

	var out []models.AffectedImage
	for rows.Next() {
		var a models.AffectedImage
		if err := rows.Scan(
			&a.ImageName, &a.ImageTag,
			&a.PkgName, &a.PkgVersion, &a.FixedVersion,
			&a.ScannedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning affected image row: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating affected image rows: %w", err)
	}
	if out == nil {
		out = []models.AffectedImage{}
	}
	return out, nil
}

// FixableSummary returns how many of the current vulnerabilities (latest scan
// per image:tag) have a known fix version available.
func (r *ScanRepository) FixableSummary(ctx context.Context, imageName string, from, to *time.Time) (*models.FixableSummary, error) {
	var fromArg, toArg any
	if from != nil {
		fromArg = *from
	}
	if to != nil {
		toArg = *to
	}

	const query = `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.image_name, s.image_tag) s.id
			FROM scans s
			WHERE ($1 = '' OR s.image_name = $1)
			  AND ($2::timestamptz IS NULL OR s.created_at >= $2::timestamptz)
			  AND ($3::timestamptz IS NULL OR s.created_at <= $3::timestamptz)
			ORDER BY s.image_name, s.image_tag, s.created_at DESC
		)
		SELECT
			COUNT(*)                                   AS total_vulns,
			COUNT(*) FILTER (WHERE v.fixed_version != '') AS fixable,
			COUNT(*) FILTER (WHERE v.fixed_version =  '') AS not_fixable
		FROM vulnerabilities v
		JOIN latest_scans ls ON ls.id = v.scan_id`

	summary := &models.FixableSummary{Image: imageName, FixableItems: []models.FixableVulnerability{}}
	if err := r.pool.QueryRow(ctx, query, imageName, fromArg, toArg).Scan(
		&summary.TotalVulns, &summary.Fixable, &summary.NotFixable,
	); err != nil {
		return nil, fmt.Errorf("querying fixable summary: %w", err)
	}

	if summary.TotalVulns > 0 {
		summary.FixablePct = float64(summary.Fixable) / float64(summary.TotalVulns) * 100
	}

	// ── Fetch fixable item details ──────────────────────────────────────────
	// Return the fixable vulnerabilities ordered by severity (critical first),
	// then CVE ID for deterministic ordering.
	const itemsQuery = `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.image_name, s.image_tag)
				s.id, s.image_name, s.image_tag
			FROM scans s
			WHERE ($1 = '' OR s.image_name = $1)
			  AND ($2::timestamptz IS NULL OR s.created_at >= $2::timestamptz)
			  AND ($3::timestamptz IS NULL OR s.created_at <= $3::timestamptz)
			ORDER BY s.image_name, s.image_tag, s.created_at DESC
		)
		SELECT
			v.cve_id,
			v.pkg_name,
			v.pkg_version,
			v.fixed_version,
			v.severity,
			v.title,
			ls.image_name,
			ls.image_tag
		FROM vulnerabilities v
		JOIN latest_scans ls ON ls.id = v.scan_id
		WHERE v.fixed_version != ''
		ORDER BY
			CASE v.severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH'     THEN 2
				WHEN 'MEDIUM'   THEN 3
				WHEN 'LOW'      THEN 4
				ELSE                 5
			END,
			v.cve_id, ls.image_name, ls.image_tag`

	rows, err := r.pool.Query(ctx, itemsQuery, imageName, fromArg, toArg)
	if err != nil {
		return nil, fmt.Errorf("querying fixable items: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item models.FixableVulnerability
		if err := rows.Scan(
			&item.CVEID, &item.PkgName, &item.PkgVersion, &item.FixedVersion,
			&item.Severity, &item.Title, &item.ImageName, &item.ImageTag,
		); err != nil {
			return nil, fmt.Errorf("scanning fixable item row: %w", err)
		}
		summary.FixableItems = append(summary.FixableItems, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating fixable item rows: %w", err)
	}

	return summary, nil
}


