package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-fuego/fuego"
	"github.com/go-fuego/fuego/extra/fuegogin"
	"github.com/go-fuego/fuego/param"
)

// RegisterRoutes wires all HTTP routes and returns the fuego Engine (for OpenAPI generation).
func RegisterRoutes(router *gin.Engine, h *ScanController, disableLocalSave bool, jsonPath string) *fuego.Engine {
	engine := fuego.NewEngine()
	engine.OpenAPI.Config.DisableLocalSave = disableLocalSave
	engine.OpenAPI.Config.DisableMessages = false
	engine.OpenAPI.Config.PrettyFormatJSON = true

	fuegogin.GetGin(engine, router, "/health", h.HealthCheck,
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: HealthResponse{}}),
	)
	fuegogin.PostGin(engine, router, "/scans", h.CreateScan,
		fuego.OptionRequestBody(fuego.RequestBody{Type: TrivyReportDTO{}, ContentTypes: []string{"application/json"}}),
		fuego.OptionAddResponse(http.StatusCreated, "Created", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/scans", h.ListScans,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("tag", "Image tag", param.Nullable()),
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQueryInt("limit", "Pagination limit", param.Nullable()),
		fuego.OptionQueryInt("offset", "Pagination offset", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScansListResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/scans/all", h.ListAllScans,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("tag", "Image tag", param.Nullable()),
		fuego.OptionQueryInt("limit", "Pagination limit", param.Nullable()),
		fuego.OptionQueryInt("offset", "Pagination offset", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScansListResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/scans/:id/vulnerabilities", h.GetScanVulnerabilities,
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQuery("pkg", "Package name filter", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanVulnerabilitiesResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/scans/latest", h.GetLatestScan,
		fuego.OptionQuery("image", "Image name", param.Required()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/summary", h.GetVulnerabilitySummary,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: VulnerabilitySummaryResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/trends", h.GetVulnerabilityTrends,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("interval", "Bucket interval", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: VulnerabilityTrendsResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/top-cves", h.GetTopCVEs,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQueryInt("limit", "Maximum results", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: TopCVEsResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/cve/:cve_id/images", h.GetCVEAffectedImages,
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: CVEAffectedImagesResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/fixable", h.GetFixableSummary,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: FixableSummaryResponseDTO{}, ContentTypes: []string{"application/json"}}),
	)
	engine.RegisterOpenAPIRoutes(&fuegogin.OpenAPIHandler{GinEngine: router})

	return engine
}
