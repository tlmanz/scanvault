-- +goose Up
-- +goose StatementBegin

-- Add pre-computed vulnerability severity counts populated at ingest time.
-- These replace the expensive JSONB lateral join queries in analytics and
-- severity-filtered listing with simple indexed integer comparisons.
ALTER TABLE scans
    ADD COLUMN vuln_critical INT NOT NULL DEFAULT 0,
    ADD COLUMN vuln_high     INT NOT NULL DEFAULT 0,
    ADD COLUMN vuln_medium   INT NOT NULL DEFAULT 0,
    ADD COLUMN vuln_low      INT NOT NULL DEFAULT 0,
    ADD COLUMN vuln_unknown  INT NOT NULL DEFAULT 0;

-- Partial indexes for the two most common severity filter patterns.
CREATE INDEX idx_scans_vuln_critical ON scans(image_name, created_at DESC) WHERE vuln_critical > 0;
CREATE INDEX idx_scans_vuln_high     ON scans(image_name, created_at DESC) WHERE vuln_high > 0;

-- Upgrade the existing GIN index (added in 002) to use jsonb_path_ops, which
-- is smaller and faster for jsonb_path_exists / @? queries.
DROP INDEX IF EXISTS idx_scans_scan_result_gin;
CREATE INDEX idx_scans_scan_result_gin ON scans USING GIN(scan_result jsonb_path_ops);

-- Back-fill counts for any scans already in the table.
UPDATE scans SET
    vuln_critical = (
        SELECT COUNT(*) FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(scan_result->'Results') = 'array' THEN scan_result->'Results' ELSE '[]'::jsonb END
        ) r, jsonb_array_elements(
            CASE WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities' ELSE '[]'::jsonb END
        ) v WHERE UPPER(v->>'Severity') = 'CRITICAL'
    ),
    vuln_high = (
        SELECT COUNT(*) FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(scan_result->'Results') = 'array' THEN scan_result->'Results' ELSE '[]'::jsonb END
        ) r, jsonb_array_elements(
            CASE WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities' ELSE '[]'::jsonb END
        ) v WHERE UPPER(v->>'Severity') = 'HIGH'
    ),
    vuln_medium = (
        SELECT COUNT(*) FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(scan_result->'Results') = 'array' THEN scan_result->'Results' ELSE '[]'::jsonb END
        ) r, jsonb_array_elements(
            CASE WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities' ELSE '[]'::jsonb END
        ) v WHERE UPPER(v->>'Severity') = 'MEDIUM'
    ),
    vuln_low = (
        SELECT COUNT(*) FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(scan_result->'Results') = 'array' THEN scan_result->'Results' ELSE '[]'::jsonb END
        ) r, jsonb_array_elements(
            CASE WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities' ELSE '[]'::jsonb END
        ) v WHERE UPPER(v->>'Severity') = 'LOW'
    ),
    vuln_unknown = (
        SELECT COUNT(*) FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(scan_result->'Results') = 'array' THEN scan_result->'Results' ELSE '[]'::jsonb END
        ) r, jsonb_array_elements(
            CASE WHEN jsonb_typeof(r->'Vulnerabilities') = 'array' THEN r->'Vulnerabilities' ELSE '[]'::jsonb END
        ) v WHERE UPPER(v->>'Severity') NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_vuln_high;
DROP INDEX IF EXISTS idx_scans_vuln_critical;
ALTER TABLE scans
    DROP COLUMN IF EXISTS vuln_unknown,
    DROP COLUMN IF EXISTS vuln_low,
    DROP COLUMN IF EXISTS vuln_medium,
    DROP COLUMN IF EXISTS vuln_high,
    DROP COLUMN IF EXISTS vuln_critical;
-- Restore the plain GIN index that was here before this migration.
CREATE INDEX IF NOT EXISTS idx_scans_scan_result_gin ON scans USING GIN(scan_result);
-- +goose StatementEnd
