// Package models contains the public domain types for ScanVault.
// Import this package to work with Scan results returned by the ScanVault API.
package models

import (
	"encoding/json"
	"time"
)

// Scan represents a stored Trivy scan result.
type Scan struct {
	ID          string          `json:"id"`
	ImageName   string          `json:"image_name"`
	ImageTag    string          `json:"image_tag"`
	ImageDigest string          `json:"image_digest"`
	ScanResult  json.RawMessage `json:"scan_result"`
	CreatedAt   time.Time       `json:"created_at"`
}
