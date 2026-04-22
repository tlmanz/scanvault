package rest

import "time"

// HealthResponse is the response envelope for health checks.
type HealthResponse struct {
	Status string `json:"status"`
}

// ScanResponseDTO is the API response DTO for one scan.
type ScanResponseDTO struct {
	ID           string         `json:"id"`
	ImageName    string         `json:"image_name"`
	ImageTag     string         `json:"image_tag"`
	ImageDigest  string         `json:"image_digest"`
	ScanResult   TrivyReportDTO `json:"scan_result"`
	CreatedAt    time.Time      `json:"created_at"`
	VulnCritical int            `json:"vuln_critical"`
	VulnHigh     int            `json:"vuln_high"`
	VulnMedium   int            `json:"vuln_medium"`
	VulnLow      int            `json:"vuln_low"`
	VulnUnknown  int            `json:"vuln_unknown"`
}

// ScansListResponseDTO is the API response DTO for scan lists.
type ScansListResponseDTO struct {
	Image    string            `json:"image,omitempty"`
	Tag      string            `json:"tag,omitempty"`
	Severity string            `json:"severity,omitempty"`
	Count    int               `json:"count"`
	Limit    int               `json:"limit,omitempty"`
	Offset   int               `json:"offset,omitempty"`
	Items    []ScanResponseDTO `json:"items"`
}

// ScanVulnerabilityItemDTO is one vulnerability item in a scan vulnerability response.
type ScanVulnerabilityItemDTO struct {
	Target        string                `json:"target"`
	Class         string                `json:"class,omitempty"`
	Type          string                `json:"type,omitempty"`
	Vulnerability TrivyVulnerabilityDTO `json:"vulnerability"`
}

// ScanVulnerabilitiesResponseDTO is the API response DTO for GET /scans/:id/vulnerabilities.
type ScanVulnerabilitiesResponseDTO struct {
	ScanID    string                     `json:"scan_id"`
	ImageName string                     `json:"image_name"`
	ImageTag  string                     `json:"image_tag"`
	Severity  string                     `json:"severity,omitempty"`
	Pkg       string                     `json:"pkg,omitempty"`
	Count     int                        `json:"count"`
	Items     []ScanVulnerabilityItemDTO `json:"items"`
}

// SeverityCountDTO is one aggregate severity bucket for analytics.
type SeverityCountDTO struct {
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

// VulnerabilityTrendPointDTO is one bucketed vulnerability count.
type VulnerabilityTrendPointDTO struct {
	Bucket   time.Time `json:"bucket"`
	Severity string    `json:"severity"`
	Count    int64     `json:"count"`
}

// TopCVEDTO is a CVE aggregated across latest scans.
type TopCVEDTO struct {
	CVEID      string `json:"cve_id"`
	Severity   string `json:"severity"`
	Title      string `json:"title,omitempty"`
	ImageCount int64  `json:"image_count"`
	Fixable    bool   `json:"fixable"`
}

// AffectedImageDTO is one image affected by a specific CVE.
type AffectedImageDTO struct {
	ImageName    string    `json:"image_name"`
	ImageTag     string    `json:"image_tag"`
	PkgName      string    `json:"pkg_name"`
	PkgVersion   string    `json:"pkg_version,omitempty"`
	FixedVersion string    `json:"fixed_version,omitempty"`
	ScannedAt    time.Time `json:"scanned_at"`
}

// FixableVulnerabilityDTO is one vulnerability with a known fix.
type FixableVulnerabilityDTO struct {
	CVEID        string `json:"cve_id"`
	PkgName      string `json:"pkg_name"`
	PkgVersion   string `json:"pkg_version,omitempty"`
	FixedVersion string `json:"fixed_version"`
	Severity     string `json:"severity"`
	Title        string `json:"title,omitempty"`
	ImageName    string `json:"image_name"`
	ImageTag     string `json:"image_tag"`
}

// VulnerabilitySummaryResponseDTO is the API response DTO for summary analytics.
type VulnerabilitySummaryResponseDTO struct {
	Image                string             `json:"image,omitempty"`
	From                 *time.Time         `json:"from,omitempty"`
	To                   *time.Time         `json:"to,omitempty"`
	TotalScans           int64              `json:"total_scans"`
	TotalVulnerabilities int64              `json:"total_vulnerabilities"`
	SeverityCounts       []SeverityCountDTO `json:"severity_counts"`
	TopCVEs              []TopCVEDTO        `json:"top_cves,omitempty"`
}

// VulnerabilityTrendsResponseDTO is the API response DTO for trends analytics.
type VulnerabilityTrendsResponseDTO struct {
	Image    string                       `json:"image,omitempty"`
	Interval string                       `json:"interval"`
	From     *time.Time                   `json:"from,omitempty"`
	To       *time.Time                   `json:"to,omitempty"`
	Count    int                          `json:"count"`
	Points   []VulnerabilityTrendPointDTO `json:"points"`
}

// TopCVEsResponseDTO is the API response DTO for top CVE analytics.
type TopCVEsResponseDTO struct {
	Image    string      `json:"image,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Limit    int         `json:"limit"`
	From     *time.Time  `json:"from,omitempty"`
	To       *time.Time  `json:"to,omitempty"`
	Count    int         `json:"count"`
	CVEs     []TopCVEDTO `json:"cves"`
}

// CVEAffectedImagesResponseDTO is the API response DTO for CVE affected images.
type CVEAffectedImagesResponseDTO struct {
	CVEID  string             `json:"cve_id"`
	Count  int                `json:"count"`
	Images []AffectedImageDTO `json:"images"`
}

// FixableSummaryResponseDTO is the API response DTO for fixable analytics.
type FixableSummaryResponseDTO struct {
	Image        string                    `json:"image,omitempty"`
	TotalVulns   int64                     `json:"total_vulns"`
	Fixable      int64                     `json:"fixable"`
	NotFixable   int64                     `json:"not_fixable"`
	FixablePct   float64                   `json:"fixable_pct"`
	FixableItems []FixableVulnerabilityDTO `json:"fixable_items"`
}
