package parser_test

import (
	"encoding/json"
	"testing"

	"github.com/tlmanz/scanvault/domain/parser"
)

func TestExtractMeta_FullPayload(t *testing.T) {
	raw := json.RawMessage(`{
		"ArtifactName": "nginx:1.25",
		"ArtifactType": "container_image",
		"Metadata": {
			"ImageID":     "sha256:abc123",
			"RepoTags":    ["nginx:1.25"],
			"RepoDigests": ["nginx@sha256:def456"]
		},
		"Results": []
	}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "nginx", meta.ImageName)
	assertEqual(t, "image_tag", "1.25", meta.ImageTag)
	assertEqual(t, "image_digest", "sha256:abc123", meta.ImageDigest)
}

func TestExtractMeta_RepoTagsOverrideArtifactName(t *testing.T) {
	// RepoTags is more precise than ArtifactName
	raw := json.RawMessage(`{
		"ArtifactName": "nginx:1.25",
		"Metadata": {
			"RepoTags": ["registry.example.com/nginx:1.25-alpine"]
		}
	}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "registry.example.com/nginx", meta.ImageName)
	assertEqual(t, "image_tag", "1.25-alpine", meta.ImageTag)
}

func TestExtractMeta_DigestFromRepoDigests(t *testing.T) {
	// Falls back to RepoDigests when ImageID is absent
	raw := json.RawMessage(`{
		"ArtifactName": "alpine:3.19",
		"Metadata": {
			"RepoDigests": ["alpine@sha256:fallback"]
		}
	}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_digest", "alpine@sha256:fallback", meta.ImageDigest)
}

func TestExtractMeta_NoTag(t *testing.T) {
	raw := json.RawMessage(`{"ArtifactName": "myimage", "Metadata": {}}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "myimage", meta.ImageName)
	assertEqual(t, "image_tag", "", meta.ImageTag)
}

func TestExtractMeta_RegistryWithPort(t *testing.T) {
	// A colon that's part of a registry host should not be split as a tag
	raw := json.RawMessage(`{"ArtifactName": "localhost:5000/myapp:v2", "Metadata": {}}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "localhost:5000/myapp", meta.ImageName)
	assertEqual(t, "image_tag", "v2", meta.ImageTag)
}

func TestExtractMeta_DigestReference_NoTag(t *testing.T) {
	raw := json.RawMessage(`{"ArtifactName": "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Metadata": {}}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "nginx", meta.ImageName)
	assertEqual(t, "image_tag", "", meta.ImageTag)
}

func TestExtractMeta_TagAndDigestReference_UsesTag(t *testing.T) {
	raw := json.RawMessage(`{"ArtifactName": "nginx:1.25@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Metadata": {}}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "nginx", meta.ImageName)
	assertEqual(t, "image_tag", "1.25", meta.ImageTag)
}

func TestExtractMeta_EmptyMetadata(t *testing.T) {
	raw := json.RawMessage(`{"ArtifactName": "busybox:latest", "Metadata": {}}`)

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertEqual(t, "image_name", "busybox", meta.ImageName)
	assertEqual(t, "image_tag", "latest", meta.ImageTag)
	assertEqual(t, "image_digest", "", meta.ImageDigest)
}

func TestExtractMeta_InvalidJSON(t *testing.T) {
	_, err := parser.ExtractMeta(json.RawMessage(`not-json`))
	if err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: want %q, got %q", field, want, got)
	}
}
