-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_scans_scan_result_gin ON scans USING GIN (scan_result);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_scan_result_gin;

-- +goose StatementEnd