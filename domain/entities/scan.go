// Package entities defines the core domain data models for ScanVault.
// These structs cross all architectural boundaries — domain, persistence,
// and presentation all speak in terms of these types.
package entities

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

	// Pre-computed vulnerability counts — populated at ingest and indexed for
	// fast severity filtering without scanning the full JSONB blob.
	VulnCritical int `json:"vuln_critical"`
	VulnHigh     int `json:"vuln_high"`
	VulnMedium   int `json:"vuln_medium"`
	VulnLow      int `json:"vuln_low"`
	VulnUnknown  int `json:"vuln_unknown"`
}

// VulnCounts holds pre-computed vulnerability counts by severity.
// Populated at ingest time by parser.CountVulnerabilities and persisted
// as indexed columns so severity queries never touch the JSONB blob.
type VulnCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// SeverityCount represents an aggregated count for one vulnerability severity.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

// VulnerabilitySummary is an aggregate view used by analytics endpoints.
type VulnerabilitySummary struct {
	Image                string          `json:"image,omitempty"`
	From                 *time.Time      `json:"from,omitempty"`
	To                   *time.Time      `json:"to,omitempty"`
	TotalScans           int64           `json:"total_scans"`
	TotalVulnerabilities int64           `json:"total_vulnerabilities"`
	SeverityCounts       []SeverityCount `json:"severity_counts"`
	TopCVEs              []TopCVE        `json:"top_cves,omitempty"`
}

// VulnerabilityTrendPoint represents one bucketed vulnerability count.
type VulnerabilityTrendPoint struct {
	Bucket   time.Time `json:"bucket"`
	Severity string    `json:"severity"`
	Count    int64     `json:"count"`
}
