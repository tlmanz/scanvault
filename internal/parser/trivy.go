package parser

import (
	"encoding/json"
	"strings"

	"github.com/distribution/reference"
)

// TrivyReport represents the top-level structure of a Trivy JSON report.
// Only the fields we care about for metadata extraction are included.
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
// It does not fail if optional fields are missing - callers can override with query params.
func ExtractMeta(raw json.RawMessage) (ImageMeta, error) {
	var report TrivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return ImageMeta{}, err
	}

	meta := ImageMeta{}

	// Parse image name and tag from ArtifactName (e.g. "nginx:1.25" or "nginx")
	if report.ArtifactName != "" {
		name, tag := splitNameTag(report.ArtifactName)
		meta.ImageName = name
		meta.ImageTag = tag
	}

	// Prefer RepoTags over ArtifactName when available for more precise tag extraction.
	if len(report.Metadata.RepoTags) > 0 {
		name, tag := splitNameTag(report.Metadata.RepoTags[0])
		if name != "" {
			meta.ImageName = name
		}
		if tag != "" {
			meta.ImageTag = tag
		}
	}

	// Extract digest - prefer ImageID, fall back to first RepoDigest.
	if report.Metadata.ImageID != "" {
		meta.ImageDigest = report.Metadata.ImageID
	} else if len(report.Metadata.RepoDigests) > 0 {
		meta.ImageDigest = report.Metadata.RepoDigests[0]
	}

	return meta, nil
}

// splitNameTag splits a Docker image reference into name and tag components.
// e.g. "nginx:1.25" → ("nginx", "1.25"), "nginx" → ("nginx", "")
// Handles registry/repo/name:tag patterns correctly.
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

	// Find the last ':' that isn't part of a port specification in a registry host.
	// Simple approach: split on ':' and check if there's a '/' after it (which would
	// indicate it's a port, not a tag).
	lastColon := strings.LastIndex(ref, ":")
	if lastColon == -1 {
		return ref, ""
	}

	potentialTag := ref[lastColon+1:]
	// A tag won't contain a '/'; that would mean it's a port number in a host.
	if strings.Contains(potentialTag, "/") {
		return ref, ""
	}

	return ref[:lastColon], potentialTag
}
