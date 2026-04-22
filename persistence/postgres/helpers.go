package postgres

import (
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tlmanz/scanvault/domain/entities"
)

// scanSingleRowFromResult scans one full scan row from a pgx.Row into an entities.Scan.
// Returns nil, nil when the row is not found (pgx.ErrNoRows).
func scanSingleRowFromResult(row pgx.Row) (*entities.Scan, error) {
	var scan entities.Scan
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

// scanRows collects multiple scan rows into an entities.Scan slice.
// Always returns a non-nil slice.
func scanRows(rows pgx.Rows) ([]entities.Scan, error) {
	var scans []entities.Scan
	for rows.Next() {
		var scan entities.Scan
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
		scans = []entities.Scan{}
	}
	return scans, nil
}

// severityColumn maps a severity string to the pre-computed column name.
// Returns an error for unrecognised values to prevent SQL injection.
func severityColumn(severity string) (string, error) {
	switch severity {
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
