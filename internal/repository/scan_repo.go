package repository

import (
	"context"
	"encoding/json"
	"fmt"
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

// Create inserts a new scan record and returns it with the server-generated fields populated.
func (r *ScanRepository) Create(ctx context.Context, imageName, imageTag, imageDigest string, scanResult json.RawMessage) (*models.Scan, error) {
	const query = `
		INSERT INTO scans (image_name, image_tag, image_digest, scan_result)
		VALUES ($1, $2, $3, $4)
		RETURNING id, image_name, image_tag, image_digest, scan_result, created_at`

	var scan models.Scan
	var rawJSON []byte

	row := r.pool.QueryRow(ctx, query, imageName, imageTag, imageDigest, []byte(scanResult))
	if err := row.Scan(
		&scan.ID,
		&scan.ImageName,
		&scan.ImageTag,
		&scan.ImageDigest,
		&rawJSON,
		&scan.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("inserting scan: %w", err)
	}

	scan.ScanResult = json.RawMessage(rawJSON)
	return &scan, nil
}

// ListByTag returns all scans for a given image tag, newest first.
func (r *ScanRepository) ListByTag(ctx context.Context, tag string) ([]models.Scan, error) {
	return r.ListByTagPage(ctx, tag, -1, 0)
}

// ListByTagPage returns scans for a tag with pagination.
// Use limit=-1 for no limit.
func (r *ScanRepository) ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]models.Scan, error) {
	const queryNoLimit = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE image_tag = $1
		ORDER BY created_at DESC
		OFFSET $2`

	const queryWithLimit = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE image_tag = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	var (
		rows pgx.Rows
		err  error
	)

	if limit < 0 {
		rows, err = r.pool.Query(ctx, queryNoLimit, tag, offset)
	} else {
		rows, err = r.pool.Query(ctx, queryWithLimit, tag, limit, offset)
	}
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

// ListByImagePage returns scans for an image with pagination.
// Use limit=-1 for no limit.
func (r *ScanRepository) ListByImagePage(ctx context.Context, imageName string, limit, offset int) ([]models.Scan, error) {
	const queryNoLimit = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE image_name = $1
		ORDER BY created_at DESC
		OFFSET $2`

	const queryWithLimit = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE image_name = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	var (
		rows pgx.Rows
		err  error
	)

	if limit < 0 {
		rows, err = r.pool.Query(ctx, queryNoLimit, imageName, offset)
	} else {
		rows, err = r.pool.Query(ctx, queryWithLimit, imageName, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("querying scans by image: %w", err)
	}
	defer rows.Close()

	return scanRows(rows)
}

// ListByImageWithSeverity returns scans for an image that contain at least one
// vulnerability with the requested severity.
func (r *ScanRepository) ListByImageWithSeverity(ctx context.Context, imageName, severity string) ([]models.Scan, error) {
	return r.ListByImageWithSeverityPage(ctx, imageName, severity, -1, 0)
}

// ListByImageWithSeverityPage returns severity-filtered scans for an image with pagination.
// Use limit=-1 for no limit.
func (r *ScanRepository) ListByImageWithSeverityPage(ctx context.Context, imageName, severity string, limit, offset int) ([]models.Scan, error) {
	const queryBase = `
		SELECT s.id, s.image_name, s.image_tag, s.image_digest, s.scan_result, s.created_at
		FROM scans s
		WHERE s.image_name = $1
		AND EXISTS (
			SELECT 1
			FROM jsonb_array_elements(
				CASE
					WHEN jsonb_typeof(s.scan_result->'Results') = 'array' THEN s.scan_result->'Results'
					ELSE '[]'::jsonb
				END
			) r
			CROSS JOIN LATERAL jsonb_array_elements(
				CASE
					WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities'
					ELSE '[]'::jsonb
				END
			) v
			WHERE UPPER(v->>'Severity') = UPPER($2)
		)
		ORDER BY s.created_at DESC`

	const queryWithLimit = `
		SELECT s.id, s.image_name, s.image_tag, s.image_digest, s.scan_result, s.created_at
		FROM scans s
		WHERE s.image_name = $1
		AND EXISTS (
			SELECT 1
			FROM jsonb_array_elements(
				CASE
					WHEN jsonb_typeof(s.scan_result->'Results') = 'array' THEN s.scan_result->'Results'
					ELSE '[]'::jsonb
				END
			) r
			CROSS JOIN LATERAL jsonb_array_elements(
				CASE
					WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities'
					ELSE '[]'::jsonb
				END
			) v
			WHERE UPPER(v->>'Severity') = UPPER($2)
		)
		ORDER BY s.created_at DESC
		LIMIT $3 OFFSET $4`

	var (
		rows pgx.Rows
		err  error
	)

	if limit < 0 {
		queryNoLimit := queryBase + "\n\t\tOFFSET $3"
		rows, err = r.pool.Query(ctx, queryNoLimit, imageName, severity, offset)
	} else {
		rows, err = r.pool.Query(ctx, queryWithLimit, imageName, severity, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("querying scans by image and severity: %w", err)
	}
	defer rows.Close()

	return scanRows(rows)
}

// LatestByImage returns the most recent scan for a given image name.
// Returns nil, nil when no scan exists for the image.
func (r *ScanRepository) LatestByImage(ctx context.Context, imageName string) (*models.Scan, error) {
	const query = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE image_name = $1
		ORDER BY created_at DESC
		LIMIT 1`

	var scan models.Scan
	var rawJSON []byte

	row := r.pool.QueryRow(ctx, query, imageName)
	if err := row.Scan(
		&scan.ID,
		&scan.ImageName,
		&scan.ImageTag,
		&scan.ImageDigest,
		&rawJSON,
		&scan.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying latest scan: %w", err)
	}

	scan.ScanResult = json.RawMessage(rawJSON)
	return &scan, nil
}

// GetByID returns a scan by ID.
// Returns nil, nil when no scan exists for the ID.
func (r *ScanRepository) GetByID(ctx context.Context, id string) (*models.Scan, error) {
	const query = `
		SELECT id, image_name, image_tag, image_digest, scan_result, created_at
		FROM scans
		WHERE id = $1
		LIMIT 1`

	var scan models.Scan
	var rawJSON []byte

	row := r.pool.QueryRow(ctx, query, id)
	if err := row.Scan(
		&scan.ID,
		&scan.ImageName,
		&scan.ImageTag,
		&scan.ImageDigest,
		&rawJSON,
		&scan.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying scan by id: %w", err)
	}

	scan.ScanResult = json.RawMessage(rawJSON)
	return &scan, nil
}

// scanRows is a helper that collects rows into a slice of Scan models.
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
		scans = []models.Scan{} // return empty slice, not nil, for clean JSON
	}
	return scans, nil
}

// DeleteOlderThan removes all scans whose created_at is older than the given duration.
// Returns the number of rows deleted.
func (r *ScanRepository) DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	const query = `DELETE FROM scans WHERE created_at < NOW() - $1::interval`
	tag, err := r.pool.Exec(ctx, query, age.String())
	if err != nil {
		return 0, fmt.Errorf("deleting old scans: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExcessPerImage keeps only the <keep> most recent scans per image name,
// deleting the rest. Returns the total number of rows deleted.
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

// DeleteExcessAndOld deletes scans that fail BOTH retention policies simultaneously:
// they must be both older than age AND ranked outside the top <keep> for their image.
//
// This is the correct query to use when both policies are active - a scan that is
// old but still within the top <keep> for its image is preserved.
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
