package rest

import (
	"time"
)

// HealthResponse is the response envelope for health checks.
type HealthResponse struct {
	Status string `json:"status"`
}

// ScanResponseDTO is the API response DTO for one scan.
type ScanResponseDTO struct {
	ID           string                 `json:"ID"`
	ImageName    string                 `json:"ImageName"`
	ImageTag     string                 `json:"ImageTag"`
	ImageDigest  string                 `json:"ImageDigest"`
	ScanResult   TrivyReportResponseDTO `json:"ScanResult"`
	CreatedAt    time.Time              `json:"CreatedAt"`
	VulnCritical int                    `json:"VulnCritical"`
	VulnHigh     int                    `json:"VulnHigh"`
	VulnMedium   int                    `json:"VulnMedium"`
	VulnLow      int                    `json:"VulnLow"`
	VulnUnknown  int                    `json:"VulnUnknown"`
}

// TrivyVulnerabilityResponseDTO represents one vulnerability in scan_result responses.
type TrivyVulnerabilityResponseDTO struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion,omitempty"`
	FixedVersion    string `json:"FixedVersion,omitempty"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title,omitempty"`
}

// TrivyResultResponseDTO represents one Trivy result section in scan_result responses.
type TrivyResultResponseDTO struct {
	Target          string                          `json:"Target,omitempty"`
	Class           string                          `json:"Class,omitempty"`
	Type            string                          `json:"Type,omitempty"`
	Vulnerabilities []TrivyVulnerabilityResponseDTO `json:"Vulnerabilities,omitempty"`
}

// TrivyMetadataResponseDTO represents image metadata in scan_result responses.
type TrivyMetadataResponseDTO struct {
	ImageID     string   `json:"ImageID,omitempty"`
	RepoTags    []string `json:"RepoTags,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
}

// TrivyReportResponseDTO represents scan_result in GET scan responses.
type TrivyReportResponseDTO struct {
	ArtifactName string                   `json:"ArtifactName,omitempty"`
	ArtifactType string                   `json:"ArtifactType,omitempty"`
	Metadata     TrivyMetadataResponseDTO `json:"Metadata,omitempty"`
	Results      []TrivyResultResponseDTO `json:"Results,omitempty"`
}

// ScansListResponseDTO is the API response DTO for scan lists.
type ScansListResponseDTO struct {
	Image    string            `json:"Image,omitempty"`
	Tag      string            `json:"Tag,omitempty"`
	Severity string            `json:"Severity,omitempty"`
	Count    int               `json:"Count"`
	Limit    int               `json:"Limit,omitempty"`
	Offset   int               `json:"Offset,omitempty"`
	Items    []ScanResponseDTO `json:"Items"`
}

// ScanVulnerabilityItemDTO is one vulnerability item in a scan vulnerability response.
type ScanVulnerabilityItemDTO struct {
	Target        string                     `json:"Target"`
	Class         string                     `json:"Class,omitempty"`
	Type          string                     `json:"Type,omitempty"`
	Vulnerability ScanVulnerabilityDetailDTO `json:"Vulnerability"`
}

// ScanVulnerabilityDetailDTO is one vulnerability detail returned by GET /scans/:id/vulnerabilities.
type ScanVulnerabilityDetailDTO struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion,omitempty"`
	CurrentVersion  string `json:"CurrentVersion,omitempty"`
	FixedVersion    string `json:"FixedVersion,omitempty"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title,omitempty"`
}

// ScanVulnerabilitiesResponseDTO is the API response DTO for GET /scans/:id/vulnerabilities.
type ScanVulnerabilitiesResponseDTO struct {
	ScanID    string                     `json:"ScanID"`
	ImageName string                     `json:"ImageName"`
	ImageTag  string                     `json:"ImageTag"`
	Severity  string                     `json:"Severity,omitempty"`
	Pkg       string                     `json:"Pkg,omitempty"`
	Count     int                        `json:"Count"`
	Items     []ScanVulnerabilityItemDTO `json:"Items"`
}

// SeverityCountDTO is one aggregate severity bucket for analytics.
type SeverityCountDTO struct {
	Severity string `json:"Severity"`
	Count    int64  `json:"Count"`
}

// VulnerabilityTrendPointDTO is one bucketed vulnerability count.
type VulnerabilityTrendPointDTO struct {
	Bucket   time.Time `json:"Bucket"`
	Severity string    `json:"Severity"`
	Count    int64     `json:"Count"`
}

// TopCVEDTO is a CVE aggregated across latest scans.
type TopCVEDTO struct {
	CVEID      string `json:"CVEID"`
	Severity   string `json:"Severity"`
	Title      string `json:"Title,omitempty"`
	ImageCount int64  `json:"ImageCount"`
	Fixable    bool   `json:"Fixable"`
}

// AffectedImageDTO is one image affected by a specific CVE.
type AffectedImageDTO struct {
	ImageName    string    `json:"ImageName"`
	ImageTag     string    `json:"ImageTag"`
	PkgName      string    `json:"PkgName"`
	PkgVersion   string    `json:"PkgVersion,omitempty"`
	FixedVersion string    `json:"FixedVersion,omitempty"`
	ScannedAt    time.Time `json:"ScannedAt"`
}

// FixableVulnerabilityDTO is one vulnerability with a known fix.
type FixableVulnerabilityDTO struct {
	CVEID        string `json:"CVEID"`
	PkgName      string `json:"PkgName"`
	PkgVersion   string `json:"PkgVersion,omitempty"`
	FixedVersion string `json:"FixedVersion"`
	Severity     string `json:"Severity"`
	Title        string `json:"Title,omitempty"`
	ImageName    string `json:"ImageName"`
	ImageTag     string `json:"ImageTag"`
}

// VulnerabilitySummaryResponseDTO is the API response DTO for summary analytics.
type VulnerabilitySummaryResponseDTO struct {
	Image                string             `json:"Image,omitempty"`
	From                 *time.Time         `json:"From,omitempty"`
	To                   *time.Time         `json:"To,omitempty"`
	TotalScans           int64              `json:"TotalScans"`
	TotalVulnerabilities int64              `json:"TotalVulnerabilities"`
	SeverityCounts       []SeverityCountDTO `json:"SeverityCounts"`
	TopCVEs              []TopCVEDTO        `json:"TopCVEs,omitempty"`
}

// VulnerabilityTrendsResponseDTO is the API response DTO for trends analytics.
type VulnerabilityTrendsResponseDTO struct {
	Image    string                       `json:"Image,omitempty"`
	Interval string                       `json:"Interval"`
	From     *time.Time                   `json:"From,omitempty"`
	To       *time.Time                   `json:"To,omitempty"`
	Count    int                          `json:"Count"`
	Points   []VulnerabilityTrendPointDTO `json:"Points"`
}

// TopCVEsResponseDTO is the API response DTO for top CVE analytics.
type TopCVEsResponseDTO struct {
	Image    string      `json:"Image,omitempty"`
	Severity string      `json:"Severity,omitempty"`
	Limit    int         `json:"Limit"`
	From     *time.Time  `json:"From,omitempty"`
	To       *time.Time  `json:"To,omitempty"`
	Count    int         `json:"Count"`
	CVEs     []TopCVEDTO `json:"CVEs"`
}

// CVEAffectedImagesResponseDTO is the API response DTO for CVE affected images.
type CVEAffectedImagesResponseDTO struct {
	CVEID  string             `json:"CVEID"`
	Count  int                `json:"Count"`
	Images []AffectedImageDTO `json:"Images"`
}

// FixableSummaryResponseDTO is the API response DTO for fixable analytics.
type FixableSummaryResponseDTO struct {
	Image        string                    `json:"Image,omitempty"`
	TotalVulns   int64                     `json:"TotalVulns"`
	Fixable      int64                     `json:"Fixable"`
	NotFixable   int64                     `json:"NotFixable"`
	FixablePct   float64                   `json:"FixablePct"`
	FixableItems []FixableVulnerabilityDTO `json:"FixableItems"`
}
