-- +goose Up
-- +goose StatementBegin

-- Before creating the unique index, remove any existing duplicate rows that
-- would violate it — keeping only the most recent scan per (image_name, image_digest).
-- This handles databases that already have historical duplicate scans.
DELETE FROM scans
WHERE id IN (
    SELECT id FROM (
        SELECT id,
            ROW_NUMBER() OVER (
                PARTITION BY image_name, image_digest
                ORDER BY created_at DESC
            ) AS rn
        FROM scans
        WHERE image_digest != ''
    ) ranked
    WHERE rn > 1
);

-- Partial unique index: enforces one row per (image_name, image_digest) but
-- ONLY when a digest is present. Empty digest (mutable tags like "latest")
-- is excluded so those can always be inserted as new historical records.
CREATE UNIQUE INDEX idx_scans_image_digest_unique
    ON scans(image_name, image_digest)
    WHERE image_digest != '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_image_digest_unique;
-- +goose StatementEnd
