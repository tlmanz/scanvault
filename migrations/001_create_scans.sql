-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS scans (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name    TEXT        NOT NULL,
    image_tag     TEXT        NOT NULL DEFAULT '',
    image_digest  TEXT        NOT NULL DEFAULT '',
    scan_result   JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_image_tag    ON scans(image_tag);
CREATE INDEX IF NOT EXISTS idx_scans_image_digest ON scans(image_digest);
CREATE INDEX IF NOT EXISTS idx_scans_image_name   ON scans(image_name);
CREATE INDEX IF NOT EXISTS idx_scans_created_at   ON scans(created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scans;
-- +goose StatementEnd
