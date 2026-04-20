package scanvault

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Option is a functional option for configuring a Server.
type Option func(*Config)

// WithLogger sets a custom zerolog.Logger on the server.
func WithLogger(l zerolog.Logger) Option {
	return func(c *Config) {
		c.Logger = &l
	}
}

// WithPort overrides the HTTP listen port.
func WithPort(port int) Option {
	return func(c *Config) {
		c.ServerPort = port
	}
}

// WithLogLevel overrides the log verbosity level.
// Accepted values: debug, info, warn, error.
func WithLogLevel(level string) Option {
	return func(c *Config) {
		c.LogLevel = level
	}
}

// WithLogFormat overrides the log output format.
// Accepted values: "json" (default, structured) or "console" (human-readable).
func WithLogFormat(format string) Option {
	return func(c *Config) {
		c.LogFormat = format
	}
}

// WithDBPool injects an existing pgxpool.Pool.
// New() will run migrations using this pool and skip internal pool creation.
func WithDBPool(pool *pgxpool.Pool) Option {
	return func(c *Config) {
		c.DBPool = pool
	}
}
