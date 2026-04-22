-- +goose Up
-- +goose StatementBegin
ALTER TABLE
  vulnerabilities RENAME TO scan_vulnerabilities_legacy;

CREATE TABLE vulnerabilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL,
  pkg_name TEXT NOT NULL,
  pkg_version TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_vulns_catalog_unique ON vulnerabilities(cve_id, pkg_name, pkg_version);

CREATE TABLE scan_vulnerabilities (
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  fixed_version TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (scan_id, vulnerability_id)
);

CREATE INDEX idx_scan_vulns_scan_id ON scan_vulnerabilities(scan_id);

CREATE INDEX idx_scan_vulns_vuln_id ON scan_vulnerabilities(vulnerability_id);

CREATE INDEX idx_scan_vulns_severity ON scan_vulnerabilities(severity);

INSERT INTO
  vulnerabilities (cve_id, pkg_name, pkg_version)
SELECT
  DISTINCT cve_id,
  pkg_name,
  pkg_version
FROM
  scan_vulnerabilities_legacy;

INSERT INTO
  scan_vulnerabilities (
    scan_id,
    vulnerability_id,
    severity,
    fixed_version,
    title
  )
SELECT
  l.scan_id,
  v.id,
  l.severity,
  l.fixed_version,
  l.title
FROM
  scan_vulnerabilities_legacy l
  JOIN vulnerabilities v ON v.cve_id = l.cve_id
  AND v.pkg_name = l.pkg_name
  AND v.pkg_version = l.pkg_version;

DROP TABLE scan_vulnerabilities_legacy;

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scan_vulnerabilities;

DROP TABLE IF EXISTS vulnerabilities;

-- +goose StatementEnd