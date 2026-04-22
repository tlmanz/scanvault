// Package parser provides stateless functions for extracting metadata and
// vulnerability data from raw Trivy JSON reports. It is pure domain logic —
// it has no dependency on persistence or presentation layers.
package parser

import (
	"encoding/json"
	"strings"

	"github.com/distribution/reference"
	"github.com/tlmanz/scanvault/domain/entities"
)

// ─── Vulnerability counting ───────────────────────────────────────────────────

type trivyVuln struct {
	Severity string `json:"Severity"`
}

type trivyResultForCount struct {
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyReportForCount struct {
	Results []trivyResultForCount `json:"Results"`
}

// CountVulnerabilities performs a single-pass count of vulnerabilities by severity
// from a raw Trivy JSON report. Missing or unrecognised severities count as Unknown.
func CountVulnerabilities(raw json.RawMessage) entities.VulnCounts {
	var report trivyReportForCount
	if err := json.Unmarshal(raw, &report); err != nil {
		return entities.VulnCounts{}
	}

	var counts entities.VulnCounts
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			switch strings.ToUpper(strings.TrimSpace(v.Severity)) {
			case "CRITICAL":
				counts.Critical++
			case "HIGH":
				counts.High++
			case "MEDIUM":
				counts.Medium++
			case "LOW":
				counts.Low++
			default:
				counts.Unknown++
			}
		}
	}
	return counts
}

// ─── Metadata extraction ──────────────────────────────────────────────────────

// TrivyReport represents the top-level structure of a Trivy JSON report.
type TrivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	ArtifactType string        `json:"ArtifactType"`
	Metadata     TrivyMetadata `json:"Metadata"`
}

// TrivyMetadata holds image-level metadata from a Trivy scan.
type TrivyMetadata struct {
	ImageID     string   `json:"ImageID"`
	RepoDigests []string `json:"RepoDigests"`
	RepoTags    []string `json:"RepoTags"`
}

// ImageMeta holds the extracted image identifiers from a Trivy report.
type ImageMeta struct {
	ImageName   string
	ImageTag    string
	ImageDigest string
}

// ExtractMeta parses a raw Trivy JSON payload and returns extracted image metadata.
// Optional fields may be absent; callers can override with query params.
func ExtractMeta(raw json.RawMessage) (ImageMeta, error) {
	var report TrivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return ImageMeta{}, err
	}

	meta := ImageMeta{}

	if report.ArtifactName != "" {
		name, tag := splitNameTag(report.ArtifactName)
		meta.ImageName = name
		meta.ImageTag = tag
	}

	if len(report.Metadata.RepoTags) > 0 {
		name, tag := splitNameTag(report.Metadata.RepoTags[0])
		if name != "" {
			meta.ImageName = name
		}
		if tag != "" {
			meta.ImageTag = tag
		}
	}

	if report.Metadata.ImageID != "" {
		meta.ImageDigest = report.Metadata.ImageID
	} else if len(report.Metadata.RepoDigests) > 0 {
		meta.ImageDigest = report.Metadata.RepoDigests[0]
	}

	return meta, nil
}

// splitNameTag splits a Docker image reference into name and tag components.
func splitNameTag(ref string) (name, tag string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}

	if named, err := reference.ParseNormalizedNamed(ref); err == nil {
		name = reference.FamiliarName(named)
		if tagged, ok := named.(reference.Tagged); ok {
			tag = tagged.Tag()
		}
		return name, tag
	}

	lastColon := strings.LastIndex(ref, ":")
	if lastColon == -1 {
		return ref, ""
	}

	potentialTag := ref[lastColon+1:]
	if strings.Contains(potentialTag, "/") {
		return ref, ""
	}

	return ref[:lastColon], potentialTag
}

// ─── Vulnerability extraction ─────────────────────────────────────────────────

type trivyFullVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

type trivyFullResult struct {
	Vulnerabilities []trivyFullVuln `json:"Vulnerabilities"`
}

type trivyFullReport struct {
	Results []trivyFullResult `json:"Results"`
}

// ExtractVulnerabilities parses all vulnerabilities from a raw Trivy JSON report
// into a flat slice ready for bulk database insertion.
// Never returns nil; returns an empty slice on parse failure or no vulnerabilities.
func ExtractVulnerabilities(raw json.RawMessage) []entities.Vulnerability {
	var report trivyFullReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return []entities.Vulnerability{}
	}

	var out []entities.Vulnerability
	seen := make(map[string]struct{})

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			key := v.VulnerabilityID + "|" + v.PkgName
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			out = append(out, entities.Vulnerability{
				CVEID:        v.VulnerabilityID,
				PkgName:      v.PkgName,
				PkgVersion:   v.InstalledVersion,
				FixedVersion: v.FixedVersion,
				Severity:     strings.ToUpper(strings.TrimSpace(v.Severity)),
				Title:        v.Title,
			})
		}
	}

	if out == nil {
		return []entities.Vulnerability{}
	}
	return out
}
