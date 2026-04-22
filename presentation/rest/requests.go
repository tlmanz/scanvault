// Package rest implements the HTTP presentation layer for ScanVault.
// Controllers, routes, and request/response types all live here.
package rest

// ─── Trivy request shapes ─────────────────────────────────────────────────────

// TrivyVulnerabilityDTO represents one vulnerability item in a Trivy report.
type TrivyVulnerabilityDTO struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion,omitempty"`
	FixedVersion    string `json:"FixedVersion,omitempty"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title,omitempty"`
}

// TrivyResultDTO represents one Trivy result section.
type TrivyResultDTO struct {
	Target          string                  `json:"Target,omitempty"`
	Class           string                  `json:"Class,omitempty"`
	Type            string                  `json:"Type,omitempty"`
	Vulnerabilities []TrivyVulnerabilityDTO `json:"Vulnerabilities,omitempty"`
}

// TrivyMetadataDTO represents image metadata included by Trivy.
type TrivyMetadataDTO struct {
	ImageID     string   `json:"ImageID,omitempty"`
	RepoTags    []string `json:"RepoTags,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
}

// TrivyReportDTO represents the request payload accepted by POST /scans.
type TrivyReportDTO struct {
	ArtifactName string           `json:"ArtifactName,omitempty"`
	ArtifactType string           `json:"ArtifactType,omitempty"`
	Metadata     TrivyMetadataDTO `json:"Metadata,omitempty"`
	Results      []TrivyResultDTO `json:"Results,omitempty"`
}
