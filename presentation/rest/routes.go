package rest

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-fuego/fuego"
	"github.com/go-fuego/fuego/extra/fuegogin"
	"github.com/go-fuego/fuego/option"
	"github.com/go-fuego/fuego/param"
)

// RegisterRoutes wires all HTTP routes and returns the fuego Engine (for OpenAPI generation).
func RegisterRoutes(router *gin.Engine, h *ScanController, disableLocalSave bool, jsonPath string) *fuego.Engine {
	engine := fuego.NewEngine(
		fuego.WithOpenAPIConfig(fuego.OpenAPIConfig{
			JSONFilePath:     jsonPath,
			PrettyFormatJSON: true,
			DisableMessages:  false,
			DisableLocalSave: disableLocalSave,
			UIHandler:        fuego.DefaultOpenAPIHandler,
			SwaggerURL:       "/swagger",
		}),
	)

	fuegogin.GetGin(engine, router, "/health", h.HealthCheck,
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: HealthResponse{}}),
		option.Summary("ScanVault Health Check"),
		option.Description("Check the health of the ScanVault service"),
		option.OperationID("HealthCheck"),
		option.Tags("System"),
	)
	fuegogin.PostGin(engine, router, "/scans", h.CreateScan,
		fuego.OptionRequestBody(fuego.RequestBody{Type: TrivyReportDTO{}, ContentTypes: []string{"application/json"}}),
		fuego.OptionAddResponse(http.StatusCreated, "Created", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Ingest Scan"),
		option.Description("Ingest a Trivy JSON vulnerability report"),
		option.OperationID("CreateScan"),
		option.Tags("Scans"),
	)
	fuegogin.GetGin(engine, router, "/scans", h.ListScans,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("tag", "Image tag", param.Nullable()),
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQueryInt("limit", "Pagination limit", param.Nullable()),
		fuego.OptionQueryInt("offset", "Pagination offset", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScansListResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("List Scans"),
		option.Description("List scans filtered by image name, tag, or severity"),
		option.OperationID("ListScans"),
		option.Tags("Scans"),
	)
	fuegogin.GetGin(engine, router, "/scans/all", h.ListAllScans,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("tag", "Image tag", param.Nullable()),
		fuego.OptionQueryInt("limit", "Pagination limit", param.Nullable()),
		fuego.OptionQueryInt("offset", "Pagination offset", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScansListResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("List All Scans"),
		option.Description("List all scans globally with optional filters"),
		option.OperationID("ListAllScans"),
		option.Tags("Scans"),
	)
	fuegogin.GetGin(engine, router, "/scans/:id/vulnerabilities", h.GetScanVulnerabilities,
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQuery("pkg", "Package name filter", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanVulnerabilitiesResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Get Scan Vulnerabilities"),
		option.Description("Get vulnerabilities for a specific scan ID"),
		option.OperationID("GetScanVulnerabilities"),
		option.Tags("Scans"),
	)
	fuegogin.GetGin(engine, router, "/scans/latest", h.GetLatestScan,
		fuego.OptionQuery("image", "Image name", param.Required()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: ScanResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Get Latest Scan"),
		option.Description("Get the most recent scan for a specific image"),
		option.OperationID("GetLatestScan"),
		option.Tags("Scans"),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/summary", h.GetVulnerabilitySummary,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: VulnerabilitySummaryResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Vulnerability Summary"),
		option.Description("Get a summary of vulnerabilities including severity counts and top CVEs"),
		option.OperationID("GetVulnerabilitySummary"),
		option.Tags("Analytics"),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/trends", h.GetVulnerabilityTrends,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("interval", "Bucket interval", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: VulnerabilityTrendsResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Vulnerability Trends"),
		option.Description("Get vulnerability trends bucketed by day or week"),
		option.OperationID("GetVulnerabilityTrends"),
		option.Tags("Analytics"),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/top-cves", h.GetTopCVEs,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("severity", "Severity filter", param.Nullable()),
		fuego.OptionQueryInt("limit", "Maximum results", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: TopCVEsResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Top CVEs"),
		option.Description("Get the top most frequently occurring CVEs"),
		option.OperationID("GetTopCVEs"),
		option.Tags("Analytics"),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/cve/:cve_id/images", h.GetCVEAffectedImages,
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: CVEAffectedImagesResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("CVE Affected Images"),
		option.Description("Get a list of all images affected by a specific CVE"),
		option.OperationID("GetCVEAffectedImages"),
		option.Tags("Analytics"),
	)
	fuegogin.GetGin(engine, router, "/analytics/vulnerabilities/fixable", h.GetFixableSummary,
		fuego.OptionQuery("image", "Image name", param.Nullable()),
		fuego.OptionQuery("from", "Start timestamp", param.Nullable()),
		fuego.OptionQuery("to", "End timestamp", param.Nullable()),
		fuego.OptionAddResponse(http.StatusOK, "OK", fuego.Response{Type: FixableSummaryResponseDTO{}, ContentTypes: []string{"application/json"}}),
		option.Summary("Fixable Vulnerabilities"),
		option.Description("Get a summary of fixable vs non-fixable vulnerabilities"),
		option.OperationID("GetFixableSummary"),
		option.Tags("Analytics"),
	)
	engine.RegisterOpenAPIRoutes(&fuegogin.OpenAPIHandler{GinEngine: router})

	return engine
}
