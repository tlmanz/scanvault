-- +goose Up
-- +goose StatementBegin

CREATE TABLE vulnerabilities (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id        TEXT        NOT NULL,
    pkg_name      TEXT        NOT NULL,
    pkg_version   TEXT        NOT NULL DEFAULT '',
    fixed_version TEXT        NOT NULL DEFAULT '',  -- '' means no fix available
    severity      TEXT        NOT NULL,
    title         TEXT        NOT NULL DEFAULT ''
);

-- Fast lookup by scan (used on every ingest)
CREATE INDEX idx_vulns_scan_id  ON vulnerabilities(scan_id);
-- CVE search across the fleet
CREATE INDEX idx_vulns_cve_id   ON vulnerabilities(cve_id);
-- Severity filter
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
-- Package analysis
CREATE INDEX idx_vulns_pkg_name ON vulnerabilities(pkg_name);

-- Prevent duplicate entries within a single scan
CREATE UNIQUE INDEX idx_vulns_unique ON vulnerabilities(scan_id, cve_id, pkg_name);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS vulnerabilities;
-- +goose StatementEnd
