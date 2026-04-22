package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/tlmanz/scanvault/domain/entities"
	"github.com/tlmanz/scanvault/domain/parser"
	"github.com/tlmanz/scanvault/domain/usecases"
)

const (
	maxListLimit         = 500
	defaultAllScansLimit = 100
)

// ScanController handles scan CRUD HTTP endpoints.
type ScanController struct {
	uc     *usecases.ScanUseCases
	logger zerolog.Logger
}

// NewScanController creates a new ScanController.
func NewScanController(uc *usecases.ScanUseCases, logger zerolog.Logger) *ScanController {
	return &ScanController{uc: uc, logger: logger}
}

// errorResponse writes a consistent JSON error envelope.
func errorResponse(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// CreateScan handles POST /scans.
func (h *ScanController) CreateScan(c *gin.Context) {
	var raw json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		errorResponse(c, http.StatusBadRequest, "request body must be valid JSON: "+err.Error())
		return
	}
	if len(raw) == 0 {
		errorResponse(c, http.StatusBadRequest, "request body must not be empty")
		return
	}

	meta, err := parser.ExtractMeta(raw)
	if err != nil {
		errorResponse(c, http.StatusBadRequest, "failed to parse Trivy JSON: "+err.Error())
		return
	}

	if imgParam := c.Query("image"); imgParam != "" {
		meta.ImageName = imgParam
	}
	if tagParam := c.Query("tag"); tagParam != "" {
		meta.ImageTag = tagParam
	}
	if digestParam := c.Query("digest"); digestParam != "" {
		meta.ImageDigest = digestParam
	}

	meta.ImageName = strings.TrimSpace(meta.ImageName)
	if meta.ImageName == "" {
		errorResponse(c, http.StatusBadRequest,
			"could not determine image_name from payload; provide ?image=<name> query param")
		return
	}

	counts := parser.CountVulnerabilities(raw)
	vulns := parser.ExtractVulnerabilities(raw)

	scan, created, err := h.uc.CreateScan(c.Request.Context(),
		meta.ImageName, meta.ImageTag, meta.ImageDigest, raw, counts, vulns)
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

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, toScanResponseDTO(scan))
}

// ListScans handles GET /scans?tag=<tag> or GET /scans?image=<name>[&severity=<level>].
func (h *ScanController) ListScans(c *gin.Context) {
	limit, offset, hasPagination, pageErr := parsePagination(c)
	if pageErr != "" {
		errorResponse(c, http.StatusBadRequest, pageErr)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	if image != "" {
		severity := strings.TrimSpace(c.Query("severity"))
		var (
			scans []entities.Scan
			err   error
		)
		if severity == "" {
			scans, err = h.uc.ListByImage(c.Request.Context(), image, limit, offset, hasPagination)
		} else {
			scans, err = h.uc.ListByImageWithSeverity(c.Request.Context(), image, severity, limit, offset, hasPagination)
		}
		if err != nil {
			h.logger.Error().Err(err).Str("image", image).Msg("failed to list scans")
			errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
			return
		}
		resp := ScansListResponseDTO{
			Image:    image,
			Severity: severity,
			Count:    len(scans),
			Items:    toScanResponseDTOList(scans),
		}
		if hasPagination {
			resp.Limit = limit
			resp.Offset = offset
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	tag := strings.TrimSpace(c.Query("tag"))
	if tag == "" {
		errorResponse(c, http.StatusBadRequest, "query parameter 'tag' or 'image' is required")
		return
	}

	scans, err := h.uc.ListByTag(c.Request.Context(), tag, limit, offset, hasPagination)
	if err != nil {
		h.logger.Error().Err(err).Str("tag", tag).Msg("failed to list scans")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
		return
	}

	resp := ScansListResponseDTO{
		Tag:   tag,
		Count: len(scans),
		Items: toScanResponseDTOList(scans),
	}
	if hasPagination {
		resp.Limit = limit
		resp.Offset = offset
	}
	c.JSON(http.StatusOK, resp)
}

// ListAllScans handles GET /scans/all.
func (h *ScanController) ListAllScans(c *gin.Context) {
	limit, offset, hasPagination, pageErr := parsePagination(c)
	if pageErr != "" {
		errorResponse(c, http.StatusBadRequest, pageErr)
		return
	}
	if !hasPagination {
		limit = defaultAllScansLimit
		offset = 0
	}

	image := strings.TrimSpace(c.Query("image"))
	tag := strings.TrimSpace(c.Query("tag"))

	scans, err := h.uc.ListAllPage(c.Request.Context(), image, tag, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list all scans")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scans")
		return
	}

	c.JSON(http.StatusOK, ScansListResponseDTO{
		Image:  image,
		Tag:    tag,
		Limit:  limit,
		Offset: offset,
		Count:  len(scans),
		Items:  toScanResponseDTOList(scans),
	})
}

// GetScanVulnerabilities handles GET /scans/:id/vulnerabilities.
func (h *ScanController) GetScanVulnerabilities(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		errorResponse(c, http.StatusBadRequest, "path parameter 'id' is required")
		return
	}

	scan, err := h.uc.GetScanByID(c.Request.Context(), id)
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

	c.JSON(http.StatusOK, ScanVulnerabilitiesResponseDTO{
		ScanID:    scan.ID,
		ImageName: scan.ImageName,
		ImageTag:  scan.ImageTag,
		Severity:  severity,
		Pkg:       pkg,
		Count:     len(matches),
		Items:     matches,
	})
}

// GetLatestScan handles GET /scans/latest?image=<name>.
func (h *ScanController) GetLatestScan(c *gin.Context) {
	imageName := strings.TrimSpace(c.Query("image"))
	if imageName == "" {
		errorResponse(c, http.StatusBadRequest, "query parameter 'image' is required")
		return
	}

	scan, err := h.uc.GetLatestScan(c.Request.Context(), imageName)
	if err != nil {
		h.logger.Error().Err(err).Str("image", imageName).Msg("failed to fetch latest scan")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve scan")
		return
	}
	if scan == nil {
		errorResponse(c, http.StatusNotFound, "no scans found for image: "+imageName)
		return
	}

	c.JSON(http.StatusOK, toScanResponseDTO(scan))
}

// HealthCheck handles GET /health.
func (h *ScanController) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{Status: "ok"})
}

// ─── Pagination helpers ───────────────────────────────────────────────────────

func parsePagination(c *gin.Context) (limit, offset int, hasPagination bool, errMsg string) {
	limitRaw := strings.TrimSpace(c.Query("limit"))
	offsetRaw := strings.TrimSpace(c.Query("offset"))

	if limitRaw == "" && offsetRaw == "" {
		return 0, 0, false, ""
	}

	hasPagination = true
	limit = -1

	if limitRaw != "" {
		parsed, err := strconv.Atoi(limitRaw)
		if err != nil {
			return 0, 0, false, "query parameter 'limit' must be an integer"
		}
		if parsed < 0 {
			return 0, 0, false, "query parameter 'limit' must be >= 0"
		}
		if parsed > maxListLimit {
			return 0, 0, false, fmt.Sprintf("query parameter 'limit' must be <= %d", maxListLimit)
		}
		limit = parsed
	}

	if offsetRaw != "" {
		parsed, err := strconv.Atoi(offsetRaw)
		if err != nil {
			return 0, 0, false, "query parameter 'offset' must be an integer"
		}
		if parsed < 0 {
			return 0, 0, false, "query parameter 'offset' must be >= 0"
		}
		offset = parsed
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

// ─── Vulnerability extraction (from stored JSONB) ─────────────────────────────

type trivyResult struct {
	Target          string                      `json:"Target"`
	Class           string                      `json:"Class"`
	Type            string                      `json:"Type"`
	Vulnerabilities []trivyScanVulnerabilityDTO `json:"Vulnerabilities"`
}

type trivyScanVulnerabilityDTO struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion,omitempty"`
	PkgVersion       string `json:"PkgVersion,omitempty"`
	FixedVersion     string `json:"FixedVersion,omitempty"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title,omitempty"`
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyReportForResponse struct {
	ArtifactName string                   `json:"ArtifactName"`
	ArtifactType string                   `json:"ArtifactType"`
	Metadata     TrivyMetadataResponseDTO `json:"Metadata"`
	Results      []trivyResultForResponse `json:"Results"`
}

type trivyResultForResponse struct {
	Target          string                      `json:"Target"`
	Class           string                      `json:"Class"`
	Type            string                      `json:"Type"`
	Vulnerabilities []trivyScanVulnerabilityDTO `json:"Vulnerabilities"`
}

func extractVulnerabilities(raw json.RawMessage, severity, pkg string) ([]ScanVulnerabilityItemDTO, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("unmarshal report: %w", err)
	}

	var out []ScanVulnerabilityItemDTO
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if !matchesSeverity(vuln, severity) || !matchesPkg(vuln, pkg) {
				continue
			}
			currentVersion := firstNonEmpty(vuln.InstalledVersion, vuln.PkgVersion)
			out = append(out, ScanVulnerabilityItemDTO{
				Target: result.Target,
				Class:  result.Class,
				Type:   result.Type,
				Vulnerability: ScanVulnerabilityDetailDTO{
					VulnerabilityID: vuln.VulnerabilityID,
					PkgName:         vuln.PkgName,
					PkgVersion:      currentVersion,
					CurrentVersion:  currentVersion,
					FixedVersion:    vuln.FixedVersion,
					Severity:        vuln.Severity,
					Title:           vuln.Title,
				},
			})
		}
	}
	if out == nil {
		out = []ScanVulnerabilityItemDTO{}
	}
	return out, nil
}

func matchesSeverity(vuln trivyScanVulnerabilityDTO, want string) bool {
	return want == "" || strings.EqualFold(vuln.Severity, want)
}

func matchesPkg(vuln trivyScanVulnerabilityDTO, want string) bool {
	return want == "" || strings.EqualFold(vuln.PkgName, want)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ─── DTO mappers ──────────────────────────────────────────────────────────────

func toScanResponseDTO(scan *entities.Scan) ScanResponseDTO {
	if scan == nil {
		return ScanResponseDTO{}
	}
	report := TrivyReportResponseDTO{}
	if len(scan.ScanResult) > 0 {
		report = mapScanResultToResponse(scan.ScanResult)
	}
	return ScanResponseDTO{
		ID:           scan.ID,
		ImageName:    scan.ImageName,
		ImageTag:     scan.ImageTag,
		ImageDigest:  scan.ImageDigest,
		ScanResult:   report,
		CreatedAt:    scan.CreatedAt,
		VulnCritical: scan.VulnCritical,
		VulnHigh:     scan.VulnHigh,
		VulnMedium:   scan.VulnMedium,
		VulnLow:      scan.VulnLow,
		VulnUnknown:  scan.VulnUnknown,
	}
}

func mapScanResultToResponse(raw json.RawMessage) TrivyReportResponseDTO {
	var source trivyReportForResponse
	if err := json.Unmarshal(raw, &source); err != nil {
		return TrivyReportResponseDTO{}
	}

	results := make([]TrivyResultResponseDTO, 0, len(source.Results))
	for _, result := range source.Results {
		vulns := make([]TrivyVulnerabilityResponseDTO, 0, len(result.Vulnerabilities))
		for _, vuln := range result.Vulnerabilities {
			currentVersion := firstNonEmpty(vuln.InstalledVersion, vuln.PkgVersion)
			vulns = append(vulns, TrivyVulnerabilityResponseDTO{
				VulnerabilityID: vuln.VulnerabilityID,
				PkgName:         vuln.PkgName,
				PkgVersion:      currentVersion,
				FixedVersion:    vuln.FixedVersion,
				Severity:        vuln.Severity,
				Title:           vuln.Title,
			})
		}
		results = append(results, TrivyResultResponseDTO{
			Target:          result.Target,
			Class:           result.Class,
			Type:            result.Type,
			Vulnerabilities: vulns,
		})
	}

	return TrivyReportResponseDTO{
		ArtifactName: source.ArtifactName,
		ArtifactType: source.ArtifactType,
		Metadata:     source.Metadata,
		Results:      results,
	}
}

func toScanResponseDTOList(scans []entities.Scan) []ScanResponseDTO {
	if len(scans) == 0 {
		return []ScanResponseDTO{}
	}
	out := make([]ScanResponseDTO, 0, len(scans))
	for i := range scans {
		out = append(out, toScanResponseDTO(&scans[i]))
	}
	return out
}
