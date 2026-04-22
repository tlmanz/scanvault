package rest

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tlmanz/scanvault/domain/entities"
)

// AnalyticsController handles vulnerability analytics HTTP endpoints.
// It is wired to the same ScanController so it shares the use-case and logger.

// GetVulnerabilitySummary handles GET /analytics/vulnerabilities/summary.
func (h *ScanController) GetVulnerabilitySummary(c *gin.Context) {
	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	summary, err := h.uc.GetVulnerabilitySummary(c.Request.Context(), image, from, to)
	if err != nil {
		h.logger.Error().Err(err).Str("image", image).Msg("failed to build vulnerability summary")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve vulnerability summary")
		return
	}

	if summary.SeverityCounts == nil {
		summary.SeverityCounts = []entities.SeverityCount{}
	}

	c.JSON(http.StatusOK, toVulnerabilitySummaryResponseDTO(summary))
}

// GetVulnerabilityTrends handles GET /analytics/vulnerabilities/trends.
func (h *ScanController) GetVulnerabilityTrends(c *gin.Context) {
	bucket := strings.ToLower(strings.TrimSpace(c.DefaultQuery("interval", "day")))
	if bucket != "day" && bucket != "week" {
		errorResponse(c, http.StatusBadRequest, "query parameter 'interval' must be 'day' or 'week'")
		return
	}

	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	image := strings.TrimSpace(c.Query("image"))
	points, err := h.uc.GetVulnerabilityTrends(c.Request.Context(), image, bucket, from, to)
	if err != nil {
		h.logger.Error().Err(err).Str("image", image).Msg("failed to build vulnerability trends")
		errorResponse(c, http.StatusInternalServerError, "failed to retrieve vulnerability trends")
		return
	}

	if points == nil {
		points = []entities.VulnerabilityTrendPoint{}
	}

	c.JSON(http.StatusOK, VulnerabilityTrendsResponseDTO{
		Image:    image,
		Interval: bucket,
		From:     from,
		To:       to,
		Count:    len(points),
		Points:   toVulnerabilityTrendPointDTOList(points),
	})
}

// GetTopCVEs handles GET /analytics/vulnerabilities/top-cves.
func (h *ScanController) GetTopCVEs(c *gin.Context) {
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

	cves, err := h.uc.GetTopCVEs(c.Request.Context(), imageName, severity, limit, from, to)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to query top CVEs")
		errorResponse(c, http.StatusInternalServerError, "failed to query top CVEs")
		return
	}

	c.JSON(http.StatusOK, TopCVEsResponseDTO{
		Image:    imageName,
		Severity: severity,
		Limit:    limit,
		Count:    len(cves),
		From:     from,
		To:       to,
		CVEs:     toTopCVEDTOList(cves),
	})
}

// GetCVEAffectedImages handles GET /analytics/vulnerabilities/cve/:cve_id/images.
func (h *ScanController) GetCVEAffectedImages(c *gin.Context) {
	cveID := strings.TrimSpace(c.Param("cve_id"))
	if cveID == "" {
		errorResponse(c, http.StatusBadRequest, "cve_id is required")
		return
	}

	images, err := h.uc.GetCVEAffectedImages(c.Request.Context(), cveID)
	if err != nil {
		h.logger.Error().Err(err).Str("cve_id", cveID).Msg("failed to query CVE affected images")
		errorResponse(c, http.StatusInternalServerError, "failed to query CVE affected images")
		return
	}

	c.JSON(http.StatusOK, CVEAffectedImagesResponseDTO{
		CVEID:  cveID,
		Count:  len(images),
		Images: toAffectedImageDTOList(images),
	})
}

// GetFixableSummary handles GET /analytics/vulnerabilities/fixable.
func (h *ScanController) GetFixableSummary(c *gin.Context) {
	imageName := c.Query("image")
	from, to, errMsg := parseTimeRange(c)
	if errMsg != "" {
		errorResponse(c, http.StatusBadRequest, errMsg)
		return
	}

	summary, err := h.uc.GetFixableSummary(c.Request.Context(), imageName, from, to)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to query fixable summary")
		errorResponse(c, http.StatusInternalServerError, "failed to query fixable summary")
		return
	}

	c.JSON(http.StatusOK, toFixableSummaryResponseDTO(summary))
}

// ─── Analytics DTO mappers ────────────────────────────────────────────────────

func toVulnerabilitySummaryResponseDTO(s *entities.VulnerabilitySummary) VulnerabilitySummaryResponseDTO {
	return VulnerabilitySummaryResponseDTO{
		Image:                s.Image,
		From:                 s.From,
		To:                   s.To,
		TotalScans:           s.TotalScans,
		TotalVulnerabilities: s.TotalVulnerabilities,
		SeverityCounts:       toSeverityCountDTOList(s.SeverityCounts),
		TopCVEs:              toTopCVEDTOList(s.TopCVEs),
	}
}

func toVulnerabilityTrendPointDTOList(points []entities.VulnerabilityTrendPoint) []VulnerabilityTrendPointDTO {
	if len(points) == 0 {
		return []VulnerabilityTrendPointDTO{}
	}
	out := make([]VulnerabilityTrendPointDTO, 0, len(points))
	for _, p := range points {
		out = append(out, VulnerabilityTrendPointDTO{Bucket: p.Bucket, Severity: p.Severity, Count: p.Count})
	}
	return out
}

func toTopCVEDTOList(cves []entities.TopCVE) []TopCVEDTO {
	if len(cves) == 0 {
		return []TopCVEDTO{}
	}
	out := make([]TopCVEDTO, 0, len(cves))
	for _, c := range cves {
		out = append(out, TopCVEDTO{CVEID: c.CVEID, Severity: c.Severity, Title: c.Title, ImageCount: c.ImageCount, Fixable: c.Fixable})
	}
	return out
}

func toAffectedImageDTOList(images []entities.AffectedImage) []AffectedImageDTO {
	if len(images) == 0 {
		return []AffectedImageDTO{}
	}
	out := make([]AffectedImageDTO, 0, len(images))
	for _, img := range images {
		out = append(out, AffectedImageDTO{
			ImageName: img.ImageName, ImageTag: img.ImageTag,
			PkgName: img.PkgName, PkgVersion: img.PkgVersion,
			FixedVersion: img.FixedVersion, ScannedAt: img.ScannedAt,
		})
	}
	return out
}

func toSeverityCountDTOList(counts []entities.SeverityCount) []SeverityCountDTO {
	if len(counts) == 0 {
		return []SeverityCountDTO{}
	}
	out := make([]SeverityCountDTO, 0, len(counts))
	for _, c := range counts {
		out = append(out, SeverityCountDTO{Severity: c.Severity, Count: c.Count})
	}
	return out
}

func toFixableSummaryResponseDTO(s *entities.FixableSummary) FixableSummaryResponseDTO {
	items := make([]FixableVulnerabilityDTO, 0, len(s.FixableItems))
	for _, v := range s.FixableItems {
		items = append(items, FixableVulnerabilityDTO{
			CVEID: v.CVEID, PkgName: v.PkgName, PkgVersion: v.PkgVersion,
			FixedVersion: v.FixedVersion, Severity: v.Severity, Title: v.Title,
			ImageName: v.ImageName, ImageTag: v.ImageTag,
		})
	}
	return FixableSummaryResponseDTO{
		Image:        s.Image,
		TotalVulns:   s.TotalVulns,
		Fixable:      s.Fixable,
		NotFixable:   s.NotFixable,
		FixablePct:   s.FixablePct,
		FixableItems: items,
	}
}
