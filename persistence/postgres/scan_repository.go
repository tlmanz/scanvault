package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tlmanz/scanvault/domain/entities"
)

// ScanRepository implements boundary.ScanPersister, boundary.ScanRetriever,
// boundary.ScanAnalytics, and boundary.ScanCleaner using PostgreSQL.
type ScanRepository struct {
	pool *pgxpool.Pool
}

// NewScanRepository creates a new ScanRepository.
func NewScanRepository(pool *pgxpool.Pool) *ScanRepository {
	return &ScanRepository{pool: pool}
}

// ─── ScanPersister ────────────────────────────────────────────────────────────

// Create inserts or updates a scan record and its vulnerability rows atomically.
func (r *ScanRepository) Create(ctx context.Context, imageName, imageTag, imageDigest string, scanResult json.RawMessage, vuln entities.VulnCounts, vulns []entities.Vulnerability) (*entities.Scan, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

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

	var scan entities.Scan
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

	// Replace vulnerability rows for this scan.
	if _, err := tx.Exec(ctx, `DELETE FROM vulnerabilities WHERE scan_id = $1`, scan.ID); err != nil {
		return nil, false, fmt.Errorf("clearing old vulnerabilities: %w", err)
	}

	if len(vulns) > 0 {
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

// ─── ScanRetriever ────────────────────────────────────────────────────────────

const selectCols = `SELECT id, image_name, image_tag, image_digest, scan_result, created_at,
       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_unknown FROM scans`

// ListByTag returns all scans for a given image tag, newest first.
func (r *ScanRepository) ListByTag(ctx context.Context, tag string) ([]entities.Scan, error) {
	return r.ListByTagPage(ctx, tag, -1, 0)
}

// ListByTagPage returns scans for a tag with optional pagination (limit=-1 = no limit).
func (r *ScanRepository) ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]entities.Scan, error) {
	base := selectCols + ` WHERE image_tag = $1 ORDER BY created_at DESC`
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
func (r *ScanRepository) ListByImage(ctx context.Context, imageName string) ([]entities.Scan, error) {
	return r.ListByImagePage(ctx, imageName, -1, 0)
}

// ListByImagePage returns scans for an image with optional pagination.
func (r *ScanRepository) ListByImagePage(ctx context.Context, imageName string, limit, offset int) ([]entities.Scan, error) {
	base := selectCols + ` WHERE image_name = $1 ORDER BY created_at DESC`
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
func (r *ScanRepository) ListAllPage(ctx context.Context, imageName, tag string, limit, offset int) ([]entities.Scan, error) {
	var q strings.Builder
	q.WriteString(selectCols + ` WHERE 1=1`)

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

// ListByImageWithSeverity returns scans with at least one vuln of the given severity.
func (r *ScanRepository) ListByImageWithSeverity(ctx context.Context, imageName, severity string) ([]entities.Scan, error) {
	return r.ListByImageWithSeverityPage(ctx, imageName, severity, -1, 0)
}

// ListByImageWithSeverityPage is the paginated variant of ListByImageWithSeverity.
func (r *ScanRepository) ListByImageWithSeverityPage(ctx context.Context, imageName, severity string, limit, offset int) ([]entities.Scan, error) {
	col, err := severityColumn(strings.ToUpper(strings.TrimSpace(severity)))
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s\n\t\tWHERE image_name = $1 AND %s > 0\n\t\tORDER BY created_at DESC", selectCols, col)

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

// LatestByImage returns the most recent scan for a given image name.
func (r *ScanRepository) LatestByImage(ctx context.Context, imageName string) (*entities.Scan, error) {
	query := selectCols + ` WHERE image_name = $1 ORDER BY created_at DESC LIMIT 1`
	return scanSingleRowFromResult(r.pool.QueryRow(ctx, query, imageName))
}

// GetByID returns a scan by its UUID.
func (r *ScanRepository) GetByID(ctx context.Context, id string) (*entities.Scan, error) {
	query := selectCols + ` WHERE id = $1 LIMIT 1`
	return scanSingleRowFromResult(r.pool.QueryRow(ctx, query, id))
}

// ─── ScanAnalytics ────────────────────────────────────────────────────────────

// VulnerabilitySummary returns aggregate vulnerability counts.
func (r *ScanRepository) VulnerabilitySummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.VulnerabilitySummary, error) {
	fromArg, toArg := timeArgs(from, to)
	summary := &entities.VulnerabilitySummary{
		Image:          imageName,
		From:           from,
		To:             to,
		SeverityCounts: []entities.SeverityCount{},
	}

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

	for _, sc := range []entities.SeverityCount{
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

	topCVEs, err := r.TopCVEs(ctx, imageName, "", 10, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying top CVEs for summary: %w", err)
	}
	summary.TopCVEs = topCVEs
	return summary, nil
}

// VulnerabilityTrends returns vulnerability counts bucketed by day or week.
func (r *ScanRepository) VulnerabilityTrends(ctx context.Context, imageName, bucket string, from, to *time.Time) ([]entities.VulnerabilityTrendPoint, error) {
	if bucket != "day" && bucket != "week" {
		return nil, fmt.Errorf("invalid bucket %q", bucket)
	}
	fromArg, toArg := timeArgs(from, to)

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

	points := []entities.VulnerabilityTrendPoint{}
	for rows.Next() {
		var p entities.VulnerabilityTrendPoint
		if err := rows.Scan(&p.Bucket, &p.Severity, &p.Count); err != nil {
			return nil, fmt.Errorf("scanning trend row: %w", err)
		}
		if p.Count > 0 {
			points = append(points, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating trend rows: %w", err)
	}
	return points, nil
}

// TopCVEs returns the most common CVEs across the latest scan of each image:tag.
func (r *ScanRepository) TopCVEs(ctx context.Context, imageName, severity string, limit int, from, to *time.Time) ([]entities.TopCVE, error) {
	if limit <= 0 {
		limit = 10
	}
	fromArg, toArg := timeArgs(from, to)

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

	out := []entities.TopCVE{}
	for rows.Next() {
		var c entities.TopCVE
		if err := rows.Scan(&c.CVEID, &c.Severity, &c.Title, &c.ImageCount, &c.Fixable); err != nil {
			return nil, fmt.Errorf("scanning top CVE row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating top CVE rows: %w", err)
	}
	return out, nil
}

// CVEAffectedImages returns all images currently exposed to a specific CVE.
func (r *ScanRepository) CVEAffectedImages(ctx context.Context, cveID string) ([]entities.AffectedImage, error) {
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

	out := []entities.AffectedImage{}
	for rows.Next() {
		var a entities.AffectedImage
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
	return out, nil
}

// FixableSummary returns how many current vulnerabilities have a known fix.
func (r *ScanRepository) FixableSummary(ctx context.Context, imageName string, from, to *time.Time) (*entities.FixableSummary, error) {
	fromArg, toArg := timeArgs(from, to)
	summary := &entities.FixableSummary{Image: imageName, FixableItems: []entities.FixableVulnerability{}}

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

	if err := r.pool.QueryRow(ctx, query, imageName, fromArg, toArg).Scan(
		&summary.TotalVulns, &summary.Fixable, &summary.NotFixable,
	); err != nil {
		return nil, fmt.Errorf("querying fixable summary: %w", err)
	}

	if summary.TotalVulns > 0 {
		summary.FixablePct = float64(summary.Fixable) / float64(summary.TotalVulns) * 100
	}

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
			v.cve_id, v.pkg_name, v.pkg_version, v.fixed_version,
			v.severity, v.title, ls.image_name, ls.image_tag
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
		var item entities.FixableVulnerability
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

// ─── ScanCleaner ─────────────────────────────────────────────────────────────

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

// DeleteExcessAndOld deletes scans that fail BOTH retention policies.
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

// ─── helpers ──────────────────────────────────────────────────────────────────

// timeArgs converts optional time.Time pointers into query arguments (nil → nil).
func timeArgs(from, to *time.Time) (any, any) {
	var f, t any
	if from != nil {
		f = *from
	}
	if to != nil {
		t = *to
	}
	return f, t
}
