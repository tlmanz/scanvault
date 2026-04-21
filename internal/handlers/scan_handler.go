package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/internal/parser"
	"github.com/tlmanz/scanvault/models"
)

// Store is the interface the handler layer requires from the data layer.
// Using an interface keeps handlers decoupled from the database and testable.
type Store interface {
	Create(ctx context.Context, imageName, imageTag, imageDigest string, scanResult json.RawMessage, vuln models.VulnCounts, vulns []models.Vulnerability) (*models.Scan, bool, error)
	ListByTag(ctx context.Context, tag string) ([]models.Scan, error)
	ListByImage(ctx context.Context, imageName string) ([]models.Scan, error)
	ListByImageWithSeverity(ctx context.Context, imageName, severity string) ([]models.Scan, error)
	LatestByImage(ctx context.Context, imageName string) (*models.Scan, error)
	GetByID(ctx context.Context, id string) (*models.Scan, error)
}

type paginatedStore interface {
	ListByTagPage(ctx context.Context, tag string, limit, offset int) ([]models.Scan, error)
	ListByImagePage(ctx context.Context, imageName string, limit, offset int) ([]models.Scan, error)
	ListByImageWithSeverityPage(ctx context.Context, imageName, severity string, limit, offset int) ([]models.Scan, error)
}

type analyticsStore interface {
	ListAllPage(ctx context.Context, imageName, tag string, limit, offset int) ([]models.Scan, error)
	VulnerabilitySummary(ctx context.Context, imageName string, from, to *time.Time) (*models.VulnerabilitySummary, error)
	VulnerabilityTrends(ctx context.Context, imageName, bucket string, from, to *time.Time) ([]models.VulnerabilityTrendPoint, error)
	TopCVEs(ctx context.Context, imageName, severity string, limit int, from, to *time.Time) ([]models.TopCVE, error)
	CVEAffectedImages(ctx context.Context, cveID string) ([]models.AffectedImage, error)
	FixableSummary(ctx context.Context, imageName string, from, to *time.Time) (*models.FixableSummary, error)
}

const maxListLimit = 500
const defaultAllScansLimit = 100

// ScanHandler holds dependencies for scan-related HTTP handlers.
type ScanHandler struct {
	store  Store
	logger zerolog.Logger
}

// New creates a new ScanHandler.
func New(store Store, logger zerolog.Logger) *ScanHandler {
	return &ScanHandler{store: store, logger: logger}
}

// errorResponse writes a consistent JSON error envelope.
func errorResponse(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// CreateScan handles POST /scans.
// It reads the raw Trivy JSON body, extracts image metadata, and stores the record.
func (h *ScanHandler) CreateScan(c *gin.Context) {
	var raw json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		errorResponse(c, http.StatusBadRequest, "request body must be valid JSON: "+err.Error())
		return
	}

	if len(raw) == 0 {
		errorResponse(c, http.StatusBadRequest, "request body must not be empty")
		return
	}

	// Extract metadata from Trivy JSON.
	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		errorResponse(c, http.StatusBadRequest, "failed to parse Trivy JSON: "+err.Error())
		return
	}

	// Allow query params to override or fill in missing metadata.
	if imgParam := c.Query("image"); imgParam != "" {
		meta.ImageName = imgParam
	}
	if tagParam := c.Query("tag"); tagParam != "" {
		meta.ImageTag = tagParam
	}
	if digestParam := c.Query("digest"); digestParam != "" {
		meta.ImageDigest = digestParam
	}

	// Require at minimum an image name.
	meta.ImageName = strings.TrimSpace(meta.ImageName)
	if meta.ImageName == "" {
		errorResponse(c, http.StatusBadRequest,
			"could not determine image_name from payload; provide ?image=<name> query param")
		return
	}

	// Count vulnerabilities by severity in a single pass — stored as indexed
	// columns so future severity queries hit the index, not the JSONB blob.
	counts := parser.CountVulnerabilities(raw)
	vulns := parser.ExtractVulnerabilities(raw)

	scan, created, err := h.store.Create(c.Request.Context(), meta.ImageName, meta.ImageTag, meta.ImageDigest, raw, counts, vulns)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to upsert scan record")
		errorResponse(c, http.StatusInternalServerError, "failed to store scan result")
		return
	}

	h.logger.Info().
		Str("id", scan.ID).
		Str("image_name", scan.ImageName).
		Str("image_tag", scan.ImageTag).
		Bool("created", created).
		Msg("scan record upserted")

	// 201 Created for new inserts, 200 OK when an existing digest record was refreshed.
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, scan)
}

// ListScans handles:
//   - GET /scans?tag=<tag>
//   - GET /scans?image=<name>[&severity=<level>]
//
// If image is provided, optional severity filters to scans that have at least
// one vulnerability with that severity.
func (h *ScanHandler) ListScans(c *gin.Context) {
	limit, offset, hasPagination, pageErr := parsePagination(c)
	if pageErr != "" {
		errorResponse(c, http.StatusBadRequest, pageErr)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	if image != "" {
		severity := strings.TrimSpace(c.Query("severity"))

		var (
			scans []models.Scan
			err   error
		)

		if severity == "" {
			scans, err = h.listByImage(c.Request.Context(), image, limit, offset, hasPagination)
		} else {
			scans, err = h.listByImageWithSeverity(c.Request.Context(), image, severity, limit, offset, hasPagination)
		}

		if err != nil {
			h.logger.Error().Err(err).Str("image", image).Str("severity", severity).Msg("failed to list scans")
			errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
			return
		}

		resp := gin.H{
			"image":    image,
			"severity": severity,
			"count":    len(scans),
			"items":    scans,
		}
		if hasPagination {
			resp["limit"] = limit
			resp["offset"] = offset
		}

		c.JSON(http.StatusOK, resp)
		return
	}

	tag := strings.TrimSpace(c.Query("tag"))
	if tag == "" {
		errorResponse(c, http.StatusBadRequest, "query parameter 'tag' or 'image' is required")
		return
	}

	scans, err := h.listByTag(c.Request.Context(), tag, limit, offset, hasPagination)
	if err != nil {
		h.logger.Error().Err(err).Str("tag", tag).Msg("failed to list scans")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
		return
	}

	resp := gin.H{
		"tag":   tag,
		"count": len(scans),
		"items": scans,
	}
	if hasPagination {
		resp["limit"] = limit
		resp["offset"] = offset
	}

	c.JSON(http.StatusOK, resp)
}

// ListAllScans handles GET /scans/all with optional image/tag filters.
func (h *ScanHandler) ListAllScans(c *gin.Context) {
	limit, offset, hasPagination, pageErr := parsePagination(c)
	if pageErr != "" {
		errorResponse(c, http.StatusBadRequest, pageErr)
		return
	}
	if !hasPagination {
		limit = defaultAllScansLimit
		offset = 0
	}

	store, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "store does not support global listing")
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	tag := strings.TrimSpace(c.Query("tag"))

	scans, err := store.ListAllPage(c.Request.Context(), image, tag, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Str("image", image).Str("tag", tag).Msg("failed to list all scans")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image":  image,
		"tag":    tag,
		"limit":  limit,
		"offset": offset,
		"count":  len(scans),
		"items":  scans,
	})
}

// GetVulnerabilitySummary handles GET /analytics/vulnerabilities/summary.
func (h *ScanHandler) GetVulnerabilitySummary(c *gin.Context) {
	store, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "store does not support vulnerability summary")
		return
	}

	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	summary, err := store.VulnerabilitySummary(c.Request.Context(), image, from, to)
	if err != nil {
		h.logger.Error().Err(err).Str("image", image).Msg("failed to build vulnerability summary")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve vulnerability summary")
		return
	}

	if summary.SeverityCounts == nil {
		summary.SeverityCounts = []models.SeverityCount{}
	}

	c.JSON(http.StatusOK, summary)
}

// GetVulnerabilityTrends handles GET /analytics/vulnerabilities/trends.
func (h *ScanHandler) GetVulnerabilityTrends(c *gin.Context) {
	store, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "store does not support vulnerability trends")
		return
	}

	bucket, errMsg := parseTrendBucket(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	points, err := store.VulnerabilityTrends(c.Request.Context(), image, bucket, from, to)
	if err != nil {
		h.logger.Error().Err(err).Str("image", image).Str("bucket", bucket).Msg("failed to build vulnerability trends")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve vulnerability trends")
		return
	}

	if points == nil {
		points = []models.VulnerabilityTrendPoint{}
	}

	c.JSON(http.StatusOK, gin.H{
		"image":    image,
		"interval": bucket,
		"from":     from,
		"to":       to,
		"count":    len(points),
		"points":   points,
	})
}

func (h *ScanHandler) listByTag(ctx context.Context, tag string, limit, offset int, hasPagination bool) ([]models.Scan, error) {
	if !hasPagination {
		return h.store.ListByTag(ctx, tag)
	}

	if pStore, ok := h.store.(paginatedStore); ok {
		return pStore.ListByTagPage(ctx, tag, limit, offset)
	}

	scans, err := h.store.ListByTag(ctx, tag)
	if err != nil {
		return nil, err
	}

	return applyPagination(scans, limit, offset), nil
}

func (h *ScanHandler) listByImage(ctx context.Context, image string, limit, offset int, hasPagination bool) ([]models.Scan, error) {
	if !hasPagination {
		return h.store.ListByImage(ctx, image)
	}

	if pStore, ok := h.store.(paginatedStore); ok {
		return pStore.ListByImagePage(ctx, image, limit, offset)
	}

	scans, err := h.store.ListByImage(ctx, image)
	if err != nil {
		return nil, err
	}

	return applyPagination(scans, limit, offset), nil
}

func (h *ScanHandler) listByImageWithSeverity(ctx context.Context, image, severity string, limit, offset int, hasPagination bool) ([]models.Scan, error) {
	if !hasPagination {
		return h.store.ListByImageWithSeverity(ctx, image, severity)
	}

	if pStore, ok := h.store.(paginatedStore); ok {
		return pStore.ListByImageWithSeverityPage(ctx, image, severity, limit, offset)
	}

	scans, err := h.store.ListByImageWithSeverity(ctx, image, severity)
	if err != nil {
		return nil, err
	}

	return applyPagination(scans, limit, offset), nil
}

func parsePagination(c *gin.Context) (limit, offset int, hasPagination bool, errMsg string) {
	limitRaw := strings.TrimSpace(c.Query("limit"))
	offsetRaw := strings.TrimSpace(c.Query("offset"))

	if limitRaw == "" && offsetRaw == "" {
		return 0, 0, false, ""
	}

	hasPagination = true
	limit = -1

	if limitRaw != "" {
		parsedLimit, err := strconv.Atoi(limitRaw)
		if err != nil {
			return 0, 0, false, "query parameter 'limit' must be an integer"
		}
		if parsedLimit < 0 {
			return 0, 0, false, "query parameter 'limit' must be >= 0"
		}
		if parsedLimit > maxListLimit {
			return 0, 0, false, fmt.Sprintf("query parameter 'limit' must be <= %d", maxListLimit)
		}
		limit = parsedLimit
	}

	if offsetRaw != "" {
		parsedOffset, err := strconv.Atoi(offsetRaw)
		if err != nil {
			return 0, 0, false, "query parameter 'offset' must be an integer"
		}
		if parsedOffset < 0 {
			return 0, 0, false, "query parameter 'offset' must be >= 0"
		}
		offset = parsedOffset
	}

	return limit, offset, true, ""
}

func parseTimeRange(c *gin.Context) (from, to *time.Time, errMsg string) {
	fromRaw := strings.TrimSpace(c.Query("from"))
	toRaw := strings.TrimSpace(c.Query("to"))

	if fromRaw != "" {
		parsed, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			return nil, nil, "query parameter 'from' must be RFC3339 (e.g. 2026-04-01T00:00:00Z)"
		}
		from = &parsed
	}

	if toRaw != "" {
		parsed, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			return nil, nil, "query parameter 'to' must be RFC3339 (e.g. 2026-04-30T23:59:59Z)"
		}
		to = &parsed
	}

	if from != nil && to != nil && from.After(*to) {
		return nil, nil, "query parameter 'from' must be before or equal to 'to'"
	}

	return from, to, ""
}

func parseTrendBucket(c *gin.Context) (bucket, errMsg string) {
	bucket = strings.ToLower(strings.TrimSpace(c.DefaultQuery("interval", "day")))
	if bucket != "day" && bucket != "week" {
		return "", "query parameter 'interval' must be 'day' or 'week'"
	}
	return bucket, ""
}

func applyPagination(scans []models.Scan, limit, offset int) []models.Scan {
	if offset >= len(scans) {
		return []models.Scan{}
	}

	end := len(scans)
	if limit >= 0 && offset+limit < end {
		end = offset + limit
	}

	return scans[offset:end]
}

// GetScanVulnerabilities handles
// GET /scans/:id/vulnerabilities?severity=<level>&pkg=<name>.
func (h *ScanHandler) GetScanVulnerabilities(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		errorResponse(c, http.StatusBadRequest, "path parameter 'id' is required")
		return
	}

	scan, err := h.store.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to fetch scan by id")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scan")
		return
	}
	if scan == nil {
		errorResponse(c, http.StatusNotFound, "scan not found: "+id)
		return
	}

	severity := strings.TrimSpace(c.Query("severity"))
	pkg := strings.TrimSpace(c.Query("pkg"))

	matches, err := extractVulnerabilities(scan.ScanResult, severity, pkg)
	if err != nil {
		h.logger.Error().Err(err).Str("id", id).Msg("failed to parse scan vulnerabilities")
		errorResponse(c, http.StatusBadRequest, "scan result is not a valid Trivy vulnerabilities payload")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":    scan.ID,
		"image_name": scan.ImageName,
		"image_tag":  scan.ImageTag,
		"severity":   severity,
		"pkg":        pkg,
		"count":      len(matches),
		"items":      matches,
	})
}

// GetLatestScan handles GET /scans/latest?image=<name>.
// Returns the most recent scan for the given image name.
func (h *ScanHandler) GetLatestScan(c *gin.Context) {
	imageName := strings.TrimSpace(c.Query("image"))
	if imageName == "" {
		errorResponse(c, http.StatusBadRequest, "query parameter 'image' is required")
		return
	}

	scan, err := h.store.LatestByImage(c.Request.Context(), imageName)
	if err != nil {
		h.logger.Error().Err(err).Str("image", imageName).Msg("failed to fetch latest scan")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scan")
		return
	}

	if scan == nil {
		errorResponse(c, http.StatusNotFound, "no scans found for image: "+imageName)
		return
	}

	c.JSON(http.StatusOK, scan)
}

// HealthCheck handles GET /health.
func (h *ScanHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type trivyResult struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Vulnerabilities []map[string]any `json:"Vulnerabilities"`
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

func extractVulnerabilities(raw json.RawMessage, severity, pkg string) ([]gin.H, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("unmarshal report: %w", err)
	}

	severity = strings.TrimSpace(severity)
	pkg = strings.TrimSpace(pkg)

	var out []gin.H
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if !matchesSeverity(vuln, severity) || !matchesPkg(vuln, pkg) {
				continue
			}

			out = append(out, gin.H{
				"target":        result.Target,
				"class":         result.Class,
				"type":          result.Type,
				"vulnerability": vuln,
			})
		}
	}

	if out == nil {
		out = []gin.H{}
	}
	return out, nil
}

func matchesSeverity(vuln map[string]any, want string) bool {
	if want == "" {
		return true
	}

	got, _ := vuln["Severity"].(string)
	return strings.EqualFold(got, want)
}

func matchesPkg(vuln map[string]any, want string) bool {
	if want == "" {
		return true
	}

	got, _ := vuln["PkgName"].(string)
	return strings.EqualFold(got, want)
}

// GetTopCVEs handles GET /analytics/vulnerabilities/top-cves
//
// Query params:
//   - image    (optional) filter to one image
//   - severity (optional) CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
//   - limit    (optional, default 10, max 100)
//   - from, to (optional RFC 3339)
func (h *ScanHandler) GetTopCVEs(c *gin.Context) {
	aStore, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "analytics not available")
		return
	}

	imageName := c.Query("image")
	severity := strings.ToUpper(strings.TrimSpace(c.Query("severity")))

	limit := 10
	if lStr := c.Query("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			if l > 100 {
				l = 100
			}
			limit = l
		}
	}

	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	cves, err := aStore.TopCVEs(c.Request.Context(), imageName, severity, limit, from, to)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to query top CVEs")
		errorResponse(c, http.StatusInternalServerError, "failed to query top CVEs")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image":    imageName,
		"severity": severity,
		"limit":    limit,
		"count":    len(cves),
		"from":     from,
		"to":       to,
		"cves":     cves,
	})
}

// GetCVEAffectedImages handles GET /analytics/vulnerabilities/cve/:cve_id/images
//
// Returns all images currently exposed to the given CVE ID.
func (h *ScanHandler) GetCVEAffectedImages(c *gin.Context) {
	aStore, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "analytics not available")
		return
	}

	cveID := strings.TrimSpace(c.Param("cve_id"))
	if cveID == "" {
		errorResponse(c, http.StatusBadRequest, "cve_id is required")
		return
	}

	images, err := aStore.CVEAffectedImages(c.Request.Context(), cveID)
	if err != nil {
		h.logger.Error().Err(err).Str("cve_id", cveID).Msg("failed to query CVE affected images")
		errorResponse(c, http.StatusInternalServerError, "failed to query CVE affected images")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cve_id": cveID,
		"count":  len(images),
		"images": images,
	})
}

// GetFixableSummary handles GET /analytics/vulnerabilities/fixable
//
// Query params:
//   - image    (optional) filter to one image
//   - from, to (optional RFC 3339)
func (h *ScanHandler) GetFixableSummary(c *gin.Context) {
	aStore, ok := h.store.(analyticsStore)
	if !ok {
		errorResponse(c, http.StatusNotImplemented, "analytics not available")
		return
	}

	imageName := c.Query("image")
	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	summary, err := aStore.FixableSummary(c.Request.Context(), imageName, from, to)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to query fixable summary")
		errorResponse(c, http.StatusInternalServerError, "failed to query fixable summary")
		return
	}

	c.JSON(http.StatusOK, summary)
}
