package migrate

import "embed"

// FS holds all SQL migration files embedded at compile time.
// Goose reads from this FS so no external migration directory is needed at runtime.
//
//go:embed *.sql
var FS embed.FS
